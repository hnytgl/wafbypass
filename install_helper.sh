#!/bin/bash

mkdir -p ~/.wafbypass/files ~/.wafbypass/tampers ~/.wafbypass/plugins

rsync -avvz content/files/* ~/.wafbypass/files
rsync -avvz content/plugins/* ~/.wafbypass/plugins
rsync -avvz content/tampers/* ~/.wafbypass/tampers
touch ~/.wafbypass/wafbypass.sqlite