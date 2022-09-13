#!/bin/bash

export $(less .env | xargs)
./target/release/orion