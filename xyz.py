import hmac
import hashlib
import json
import os
from flask import Flask, request, abort

app = Flask(__name__)

# Load your secret from an environment variable for security
GITHUB_SECRET = os.environ.get('GITHUB_WEBHOOK_SECRET', 'your_secret_here')
TARGET_BRANCH = 'refs/heads/main'


def verify_signature(payload_body, header_signature):
    """Verify that the payload was sent from GitHub by validating the HMAC."""
    if not header_signature:
        return False

    sha_name, signature = header_signature.split('=')
    if sha_name != 'sha256':
        return False

    # Create local hash using your secret and the raw request body
    local_hash = hmac.new(
        GITHUB_SECRET.encode(),
        payload_body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(local_hash, signature)


@app.route('/webhook', methods=['POST'])
def github_webhook():
    # 1. Validate HMAC Signature
    signature = request.headers.get('X-Hub-Signature-256')
    if not verify_signature(request.data, signature):
        abort(403, "Invalid signature")

    # 2. Parse Payload
    payload = request.json
    if not payload:
        abort(400, "No payload received")

    # 3. Extract Metadata
    repo_name = payload.get('repository', {}).get('full_name')
    branch = payload.get('ref')  # Format: refs/heads/main
    commit_sha = payload.get('after')
    pusher_name = payload.get('pusher', {}).get('name')
    timestamp = payload.get('head_commit', {}).get('timestamp')

    # 4. Filter by Branch and Trigger Pipeline
    if branch == TARGET_BRANCH:
        print(f"🚀 Triggering deploy for {repo_name}...")
        print(f"Commit: {commit_sha} by {pusher_name} at {timestamp}")

        # Insert your deployment logic here (e.g., call a script or subprocess)
        # execute_deploy_script(repo_name, commit_sha)

        return "Deployment triggered", 200
    else:
        return f"Push to {branch} ignored. Target is {TARGET_BRANCH}.", 200


if __name__ == '__main__':
    # Use a production-ready server like Gunicorn in a real environment
    app.run(host='0.0.0.0', port=5000)
