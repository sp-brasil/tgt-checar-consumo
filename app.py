from flask import Flask, request, jsonify
import requests
import json
from datetime import datetime
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import traceback

app = Flask(__name__)

# --- Credenciais de Produção ---
ACCOUNT_ID = "RE_simpremium"
SIGN_KEY = "3GIJ0119BNP3G6UN6A5I6BB4PZS2QVWQ"
SECRET_KEY = "UYHUR49SEVWFR6WI"
VECTOR = "OQ75CK0MYKQDKC0O"
API_VERSION = "1.0"
BASE_URL = "http://enterpriseapi.tugegroup.com:8060/api-publicappmodule/"

# --- Funções de Criptografia e Assinatura ---
def aes_encrypt(data_str):
    key = SECRET_KEY.encode('utf-8')
    iv = VECTOR.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data_str.encode('utf-8'), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    return ''.join([f"{chr(((b >> 4) & 0xF) + ord('a'))}{chr(((b & 0xF) + ord('a')))}" for b in encrypted_bytes])

def aes_decrypt(encrypted_hex):
    key = SECRET_KEY.encode('utf-8')
    iv = VECTOR.encode('utf-8')
    encrypted_bytes = bytes([((ord(encrypted_hex[i]) - ord('a')) << 4) + (ord(encrypted_hex[i+1]) - ord('a')) for i in range(0, len(encrypted_hex), 2)])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded_bytes = cipher.decrypt(encrypted_bytes)
    unpadded_bytes = unpad(decrypted_padded_bytes, AES.block_size)
    return unpadded_bytes.decode('utf-8')

def create_signature(service_name, request_time, encrypted_data):
    raw_string = f"{ACCOUNT_ID}{service_name}{request_time}{encrypted_data}{API_VERSION}{SIGN_KEY}"
    md5_hash = hashlib.md5(raw_string.encode('utf-8')).hexdigest()
    return md5_hash

# --- Rota para Consultar Consumo de um Único eSIM ---
@app.route('/get_usage', methods=['POST'])
def get_esim_usage():
    try:
        request_body = request.get_json()
        if not request_body:
            return jsonify({"error": "Request body is missing or not JSON"}), 400
        
        iccid = request_body.get("iccid")
        order_no = request_body.get("orderNo")

        if not iccid or not order_no:
            return jsonify({"error": "Missing required fields: iccid and orderNo"}), 400
            
        service_name = "getEsimFlowByParams"
        endpoint = "saleSimApi/getEsimFlowByParams"
        
        data_payload = {
            "iccid": iccid,
            "orderNo": order_no,
            "lang": request_body.get("lang", "en")
        }

        data_str = json.dumps(data_payload)
        encrypted_data = aes_encrypt(data_str)
        request_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        sign = create_signature(service_name, request_time, encrypted_data)

        final_payload = { "accountId": ACCOUNT_ID, "serviceName": service_name, "requestTime": request_time, "data": encrypted_data, "version": API_VERSION, "sign": sign }
        headers = {'Content-Type': 'application/json'}

        response = requests.post(BASE_URL + endpoint, data=json.dumps(final_payload), headers=headers, timeout=20)
        response.raise_for_status()
        
        response_json = response.json()

        if response_json.get("code") == "0000":
            decrypted_data = aes_decrypt(response_json["data"])
            return jsonify(json.loads(decrypted_data)), 200
        else:
            return jsonify({"error": response_json}), 400

    except Exception as e:
        print("!!!!!!!!!! ERRO DETALHADO EM /get_usage !!!!!!!!!!")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False)