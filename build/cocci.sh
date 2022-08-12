#!/bin/sh

echo docker run -it --rm -v "$(pwd)":/workspace --user root coccinelle:latest /bin/bash
echo cd /workspace
echo 'spatch --sp-file build/coccinelle/convert_u_int_form.cocci -I include -I lib --in-place --dir {include,lib,src,test}'
