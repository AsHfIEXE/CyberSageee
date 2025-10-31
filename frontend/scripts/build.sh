#!/bin/bash

echo "🚀 Building CyberSage Frontend for Production..."

# Set production environment
export GENERATE_SOURCEMAP=false
export NODE_ENV=production

# Build the application
npm run build

# Create production package
echo "📦 Creating production package..."
tar -czf ../CyberSage-Frontend-Production.tar.gz build/

echo "✅ Build completed successfully!"
echo "📁 Production files in: ./build/"
echo "📦 Production package: ../CyberSage-Frontend-Production.tar.gz"