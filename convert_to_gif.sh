#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: ./convert_to_gif.sh video.mp4"
    exit 1
fi
ffmpeg -i "$1" -vf "fps=10,scale=800:-1:flags=lanczos" -c:v gif -f gif demo.gif
echo "✅ GIF created: demo.gif"

