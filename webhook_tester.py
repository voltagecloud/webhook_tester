#!/usr/bin/env python3
import json
import argparse
import http.server
import socketserver
import hashlib
import hmac
import base64
from datetime import datetime
from typing import Dict, Any, Optional, List, cast
import logging
import os
import sys


# Create a custom formatter for cleaner output
class WebhookFormatter(logging.Formatter):
    def __init__(self):
        super().__init__()
        # We'll use different formats based on log level
        self.info_fmt = "%(message)s"
        self.debug_fmt = "  %(message)s"  # Indented for readability
        self.error_fmt = "ERROR: %(message)s"

    def format(self, record):
        # Save the original format
        original_fmt = self._style._fmt

        # Apply different format based on log level
        if record.levelno == logging.DEBUG:
            self._style._fmt = self.debug_fmt
        elif record.levelno == logging.INFO:
            self._style._fmt = self.info_fmt
        elif record.levelno in (logging.ERROR, logging.WARNING):
            self._style._fmt = self.error_fmt

        # Format the message
        result = super().format(record)

        # Restore the original format
        self._style._fmt = original_fmt

        return result


class WebhookServer(socketserver.TCPServer):
    """Custom TCPServer that stores received webhooks and verification info."""

    def __init__(self, server_address, RequestHandlerClass, shared_secret=None, output_file=None, truncate_output=False):
        self.shared_secret: Optional[str] = shared_secret
        self.received_webhooks: List[Dict[str, Any]] = []
        self.output_file: Optional[str] = output_file

        if output_file and truncate_output:
            with open(output_file, 'w') as f:
                f.write('[]')

        super().__init__(server_address, RequestHandlerClass)


class WebhookHandler(http.server.BaseHTTPRequestHandler):
    """Handler for webhook requests."""

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))

        body = self.rfile.read(content_length).decode('utf-8')
        payload = json.loads(body) if body else {}

        headers_dict = dict(self.headers.items())
        signature = headers_dict.get('x-voltage-signature')
        timestamp = headers_dict.get('x-voltage-timestamp')
        event_type = headers_dict.get('x-voltage-event')

        webhook_data = {
            'timestamp': datetime.now().isoformat(),
            'path': self.path,
            'headers': headers_dict,
            'payload': payload,
            'signature': signature,
            'event_type': event_type,
        }

        server = cast(WebhookServer, self.server)
        server.received_webhooks.append(webhook_data)

        # Verify signature (only once)
        signature_valid = None
        if server.shared_secret is not None and signature is not None and timestamp is not None:
            signature_valid = self.verify_signature(body, signature, timestamp, server.shared_secret)
            webhook_data['signature_valid'] = signature_valid

        # Log webhook info in a cleaner format
        logging.info("=" * 60)
        logging.info(f"WEBHOOK #{len(server.received_webhooks)} RECEIVED: {event_type or 'Unknown'}")
        logging.info(f"Time: {webhook_data['timestamp']}")

        if signature_valid is not None:
            status = "✓ VALID" if signature_valid else "✗ INVALID"
            logging.info(f"Signature: {status}")

        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug(f"Path: {self.path}")
            logging.debug("Headers:")
            for key, value in headers_dict.items():
                logging.debug(f"{key}: {value}")
            logging.debug("Payload:")
            payload_json = json.dumps(payload, indent=2)
            # Indent each line of the payload for better readability
            for line in payload_json.split('\n'):
                logging.debug(line)

        logging.info("=" * 60 + "\n")

        if server.output_file:
            try:
                try:
                    with open(server.output_file, 'r') as f:
                        try:
                            existing_webhooks = json.load(f)
                        except json.JSONDecodeError:
                            existing_webhooks = []
                except FileNotFoundError:
                    existing_webhooks = []

                existing_webhooks.append(webhook_data)

                with open(server.output_file, 'w') as f:
                    json.dump(existing_webhooks, f, indent=2)

            except Exception as e:
                logging.error(f"Failed to write to output file: {e}")

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = json.dumps({
            "status": "success",
            "message": "Webhook received successfully"
        })
        self.wfile.write(response.encode('utf-8'))

    # Suppress server logs
    def log_message(self, format, *args):
        return

    @staticmethod
    def verify_signature(payload: str, signature: str, timestamp: str, shared_secret: str) -> bool:
        """
        Verify the webhook signature using HMAC-SHA256.

        Args:
            payload: The webhook payload as a string
            signature: The signature from the webhook header
            timestamp: The timestamp from the webhook header
            shared_secret: The shared secret used to sign the webhook

        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            # Ensure shared_secret is not None or empty
            if not shared_secret:
                logging.warning("Cannot verify signature: shared_secret is None or empty")
                return False

            # Create message from payload and timestamp
            message = f"{payload}.{timestamp}"

            # Create HMAC
            hmac_obj = hmac.new(
                shared_secret.encode('utf-8'),
                message.encode('utf-8'),
                hashlib.sha256
            )

            # Get digest
            expected_signature = base64.b64encode(hmac_obj.digest()).decode('utf-8')

            # Compare signatures
            return hmac.compare_digest(expected_signature, signature)
        except Exception as e:
            logging.error(f"Error verifying signature: {e}")
            return False


def create_default_config(config_path):
    """Create a default configuration file if it doesn't exist."""
    default_config = {
        "host": "localhost",
        "port": 7999,
        "secret": None,
        "output_file": "webhooks.json",
        "truncate_output": False,
        "log_level": "INFO"
    }

    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)

    with open(config_path, 'w') as f:
        json.dump(default_config, f, indent=2)

    print(f"Created default configuration file at: {config_path}")
    return default_config


def setup_logging(level):
    """Set up custom logging configuration"""
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create custom handler with our formatter
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(WebhookFormatter())
    root_logger.addHandler(handler)


def main():
    parser = argparse.ArgumentParser(description='Simple webhook receiver for testing webhooks')
    parser.add_argument('--config', type=str, default='webhook_config.json', help='Configuration file path')

    args = parser.parse_args()

    if not os.path.exists(args.config):
        config = create_default_config(args.config)
    else:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except json.JSONDecodeError:
            print(f"Invalid JSON in configuration file: {args.config}. Creating new default config.")
            config = create_default_config(args.config)

    log_level_name = config.get('log_level', 'INFO').upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    # Set up custom logging
    setup_logging(log_level)

    host = config.get('host', 'localhost')
    port = config.get('port', 7999)
    secret = config.get('secret')
    output_file = config.get('output_file', 'webhooks.json')
    truncate_output = config.get('truncate_output', False)

    server = WebhookServer(
        (host, port),
        WebhookHandler,
        shared_secret=secret,
        output_file=output_file,
        truncate_output=truncate_output
    )

    logging.info(f"Starting webhook server on http://{host}:{port}")
    logging.info(f"Log level: {log_level_name}")
    logging.info(f"Shared secret {'configured' if secret else 'not configured'}")
    logging.info(f"Writing webhooks to {output_file}")
    logging.info("Press Ctrl+C to stop the server\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("\nShutting down webhook server...")

        if server.received_webhooks:
            logging.info(f"Received {len(server.received_webhooks)} webhooks during this session")
            for i, webhook in enumerate(server.received_webhooks, 1):
                event_type = webhook.get('event_type', 'Unknown')
                path = webhook.get('path', '/')
                timestamp = webhook.get('timestamp', 'Unknown')
                logging.info(f"  {i}. {event_type} - {path} - {timestamp}")
        else:
            logging.info("No webhooks were received during this session.")


        server.server_close()
        logging.info("Server stopped.")

    except Exception as e:
        logging.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
