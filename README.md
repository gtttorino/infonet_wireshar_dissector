# infonet_wireshark_dissector
This plugin parses UDP packets from Infonet protocol

A Wireshark Dissector for infonet UDP Packets written in LUA

To install simply download and copy infonet.lua into Wireshark's "Personal Lua Plugins" folder or "Global Lua Plugins" folder.
To locate this folder in Wireshark goto Help -> About -> Folders Tab.
To check if the script is loaded goto Help -> About -> Plugins. The Type will be "lua script"
Ctrl + Shift + L will reload Lua scripts without needing to restart.

The proto declaration is "infonet" and the protofields have been added using the format infonet.$header$".
![image](https://github.com/user-attachments/assets/4064b941-674b-4737-bbf7-e8433207017b)
