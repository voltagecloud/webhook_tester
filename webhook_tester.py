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


class WebhookServer(socketserver.TCPServer):
    """Custom TCPServer that stores received webhooks and verification info."""

    def __init__(self, server_address, RequestHandlerClass, shared_secret=None, verbose=False):
        self.shared_secret: Optional[str] = shared_secret
        self.verbose: bool = verbose
        self.received_webhooks: List[Dict[str, Any]] = []
        super().__init__(server_address, RequestHandlerClass)


class WebhookHandler(http.server.BaseHTTPRequestHandler):
    """Handler for webhook requests."""

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))

        # Read request body
        body = self.rfile.read(content_length).decode('utf-8')
        payload = json.loads(body) if body else {}

        # Get headers - convert to dict for easier handling
        headers_dict = dict(self.headers.items())
        signature = headers_dict.get('x-voltage-signature')
        timestamp = headers_dict.get('x-voltage-timestamp')
        event_type = headers_dict.get('x-voltage-event')

        # Store request details
        webhook_data = {
            'timestamp': datetime.now().isoformat(),
            'path': self.path,
            'headers': headers_dict,
            'payload': payload,
            'signature': signature,
            'event_type': event_type,
        }

        # Get server instance (explicitly cast to our custom server type)
        server = cast(WebhookServer, self.server)
        server.received_webhooks.append(webhook_data)

        # Log the webhook
        if server.verbose:
            print(f"\n{'=' * 50}")
            print(f"WEBHOOK RECEIVED ({len(server.received_webhooks)})")
            print(f"Time: {webhook_data['timestamp']}")
            print(f"Path: {self.path}")
            print(f"Event Type: {event_type}")
            print("\nHeaders:")
            for key, value in headers_dict.items():
                print(f"  {key}: {value}")
            print("\nPayload:")
            print(json.dumps(payload, indent=2))

            # If shared secret is provided, verify signature
            if server.shared_secret is not None and signature is not None and timestamp is not None:
                is_valid = self.verify_signature(body, signature, timestamp, server.shared_secret)
                print(f"\nSignature verification: {'✓ VALID' if is_valid else '✗ INVALID'}")

            print(f"{'=' * 50}\n")

        # Send response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = json.dumps({
            "status": "success",
            "message": "Webhook received successfully"
        })
        self.wfile.write(response.encode('utf-8'))

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
                print("Cannot verify signature: shared_secret is None or empty")
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
            print(f"Error verifying signature: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description='Simple webhook receiver for testing webhooks')
    parser.add_argument('--port', type=int, default=8000, help='Port to listen on (default: 8000)')
    parser.add_argument('--host', type=str, default='localhost', help='Host to bind to (default: localhost)')
    parser.add_argument('--secret', type=str, help='Shared secret for signature verification')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Default to verbose output if not specified
    verbose = True if args.verbose is None else args.verbose

    # Create server with shared secret
    server = WebhookServer(
        (args.host, args.port),
        WebhookHandler,
        shared_secret=args.secret,
        verbose=verbose
    )

    # Start server
    print(f"Starting webhook server on http://{args.host}:{args.port}")
    print(f"Shared secret {'configured' if args.secret else 'not configured'}")
    print("Press Ctrl+C to stop the server")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down webhook server...")

        if server.received_webhooks:
            print(f"\nReceived {len(server.received_webhooks)} webhooks:")
            for i, webhook in enumerate(server.received_webhooks, 1):
                event_type = webhook.get('event_type', 'Unknown')
                path = webhook.get('path', '/')
                timestamp = webhook.get('timestamp', 'Unknown')
                print(f"{i}. {event_type} - {path} - {timestamp}")

            save = input("\nDo you want to save received webhooks to a file? (y/n): ")
            if save.lower() == 'y':
                filename = input("Enter filename (default: webhooks.json): ") or "webhooks.json"
                with open(filename, 'w') as f:
                    json.dump(server.received_webhooks, f, indent=2)
                print(f"Webhooks saved to {filename}")
        else:
            print("No webhooks were received during this session.")

        server.server_close()
        print("Server stopped.")


if __name__ == "__main__":
    main()
