echo Run Python

source ~/dlp-llm-proxy/dlp-engine/llm_dlp_engine_ollama/.venv/bin/activate

echo Run upload server

python3 ~/dlp-llm-proxy/dlp-test-server/upload_server.py &

echo Run uvicorn 

cd ~/dlp-llm-proxy/dlp-engine/llm_dlp_engine_ollama

python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 &

echo Run Secure Server 

cd ~/dlp-llm-proxy/dlp-https-server/

python3 https_server.py &

echo Run Proxy 
cd ~/dlp-llm-proxy/dlp-proxy

mitmdump --mode regular --listen-host 0.0.0.0 --listen-port 8080 --set ssl_insecure=true -s addon.py &

echo Run dashboard

cd ~/dlp-llm-proxy/dashboard

streamlit run dashboard.py &
