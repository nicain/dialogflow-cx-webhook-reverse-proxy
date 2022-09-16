#!/bin/bash

nginx &
cd frontend && npm start &

export FLASK_DEBUG=1 && PROD=false && flask run --port 5001 --host=0.0.0.0