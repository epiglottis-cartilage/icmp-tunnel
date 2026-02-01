#! /bin/sh
sudo nft add table inet filter
sudo nft -f ./rules.nft
