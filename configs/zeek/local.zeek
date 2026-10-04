# QuantumSafe-IDS local Zeek site policy
@load base/protocols/conn
@load base/protocols/ssl
@load base/protocols/http
@load base/frameworks/notice

redef LogAscii::use_json = F;
