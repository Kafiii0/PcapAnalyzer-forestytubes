## Alur singkatnya training

```text
Wireshark capture traffic normal
↓
save normal-traffic.pcapng
↓
extractor.exe normal-traffic.pcapng
↓
muncul output.json
↓
rename output.json jadi normal-traffic-1.json
↓
npm run train -- normal-traffic-1.json

Start awal
./setup.bat
