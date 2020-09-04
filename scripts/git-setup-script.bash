#!/bin/bash

git init
git remote add origin git@github.com:kaviarjs/$1.git
git add .
git commit -m "Initial commit"
git push -u origin master