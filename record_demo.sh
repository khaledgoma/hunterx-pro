#!/bin/bash
echo "🎥 Recording HunterX Demo..."
echo "1. Start the app first: python3 app.py"
echo "2. Then run this script"
echo ""
echo "Recording options:"
echo "  A) Record terminal demo (HunterX CLI)"
echo "  B) Record web dashboard demo"
read -p "Choice (A/B): " choice

if [ "$choice" = "A" ]; then
    script --timing=demo.timing demo_script.txt
    echo "Recording saved."
elif [ "$choice" = "B" ]; then
    sudo apt install simplescreenrecorder -y 2>/dev/null
    simplescreenrecorder
fi
