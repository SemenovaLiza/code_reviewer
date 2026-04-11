#!/bin/bash

# Run first process (in background)
python3 agents/copy_embeddings.py &

# Run second process (main one)
python3 main.py