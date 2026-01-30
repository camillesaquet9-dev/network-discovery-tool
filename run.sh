#!/bin/bash

echo "Lancement du scan reseau automatise..."
echo ""

if [ "$EUID" -ne 0 ]; then
  echo "AVERTISSEMENT: Ce script necessite les privileges root"
  echo "Relancez avec: sudo ./run.sh"
  echo ""
fi

cd "$(dirname "$0")"

python3 src/principal.py "$@"
