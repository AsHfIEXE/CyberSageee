#!/bin/bash

echo "🌐 Serving CyberSage Frontend..."

if [[ ! -d "build" ]]; then
    echo "❌ Build directory not found. Please run: npm run build"
    exit 1
fi

echo "📡 Serving on http://localhost:3000"
npx serve -s build -l 3000