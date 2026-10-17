#!/usr/bin/env bash

if [[ -z "${FLAG_2:-}" ]]; then
  echo "WARNING: FLAG_2 is not set"
fi

# --- Replace placeholder in /app/flag ---
if [[ -f "/app/flag" ]]; then
  if grep -q "REPLACE_THIS_STRING_WITH_SERVER_FLAG" "/app/flag"; then
    echo "Initializing /app/flag"
    sed -i "s/REPLACE_THIS_STRING_WITH_SERVER_FLAG/${FLAG_2}/g" /app/flag
    chmod 600 /app/flag
  fi
else
  echo "WARNING: /app/flag not found, skipping"
fi

# --- Start the server ---
# The flag is only needed to set up /app/flag, so keep it out of the server's environment.
unset FLAG_2
echo "Starting server..."
# Keep one worker: RMAP holds each handshake in memory between its two requests.
exec gosu appuser gunicorn -b 0.0.0.0:5000 --access-logfile - server:app

