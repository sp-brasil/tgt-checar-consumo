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

# --- Rota para Buscar Histórico Completo e Consumo Atual por ICCID ---
@app.route('/get_iccid_history', methods=['POST'])
def get_iccid_history():
    try:
        request_body = request.get_json()
        if not request_body:
            return jsonify({"error": "Request body is missing or not JSON"}), 400
        
        iccid = request_body.get("iccid")
        if not iccid:
            return jsonify({"error": "Missing required field: iccid"}), 400

        # 1. BUSCAR TODOS OS PEDIDOS (de todos os status) PARA ESTE ICCID
        service_name_orders = "queryEsimOrderList"
        endpoint_orders = "saleOrderApi/queryEsimOrderList"
        # Deixamos 'orderStatus' em branco para pegar todos
        data_payload_orders = { "page": 1, "pageSize": 100, "iccid": iccid, "orderStatus": "", "lang": "en" }
        
        data_str = json.dumps(data_payload_orders)
        encrypted_data = aes_encrypt(data_str)
        request_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        sign = create_signature(service_name_orders, request_time, encrypted_data)
        final_payload = { "accountId": ACCOUNT_ID, "serviceName": service_name_orders, "requestTime": request_time, "data": encrypted_data, "version": API_VERSION, "sign": sign }
        headers = {'Content-Type': 'application/json'}

        response_orders = requests.post(BASE_URL + endpoint_orders, data=json.dumps(final_payload), headers=headers, timeout=20)
        response_orders.raise_for_status()
        response_orders_json = response_orders.json()

        if response_orders_json.get("code") != "0000":
            return jsonify({"error": "Failed to fetch orders for ICCID", "details": response_orders_json}), 400

        all_orders = json.loads(aes_decrypt(response_orders_json["data"]))
        
        if not all_orders:
            return jsonify([]), 200

        detailed_results = []
        
        # 2. PARA CADA PEDIDO ENCONTRADO, VERIFICAR O STATUS
        for order in all_orders:
            order_status = order.get("orderStatus")
            order_no = order.get("orderNo")
            
            # 3. SE O PEDIDO ESTIVER "EM USO", BUSCAR O CONSUMO ATUAL
            if order_status == "INUSE":
                service_name_flow = "getEsimFlowByParams"
                endpoint_flow = "saleSimApi/getEsimFlowByParams"
                data_payload_flow = { "iccid": iccid, "orderNo": order_no, "lang": "en" }
                
                data_str_flow = json.dumps(data_payload_flow)
                encrypted_data_flow = aes_encrypt(data_str_flow)
                request_time_flow = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                sign_flow = create_signature(service_name_flow, request_time_flow, encrypted_data_flow)
                final_payload_flow = { "accountId": ACCOUNT_ID, "serviceName": service_name_flow, "requestTime": request_time_flow, "data": encrypted_data_flow, "version": API_VERSION, "sign": sign_flow }

                response_flow = requests.post(BASE_URL + endpoint_flow, data=json.dumps(final_payload_flow), headers=headers, timeout=20)
                
                usage_data = {}
                if response_flow.status_code == 200 and response_flow.json().get("code") == "0000":
                    usage_data = json.loads(aes_decrypt(response_flow.json()["data"]))
                
                # Monta o resultado detalhado com consumo
                combined_result = {
                    "iccid": iccid,
                    "orderNo": order_no,
                    "productName": order.get("productName"),
                    "status": order_status,
                    "validity_start_date": order.get("startDate"),
                    "validity_end_date": order.get("endDate"),
                    "daily_total_mb": usage_data.get("dataTotal"),
                    "daily_usage_mb": usage_data.get("qtaconsumption") or usage_data.get("dataUsage"),
                    "daily_remaining_mb": usage_data.get("dataResidual")
                }
                detailed_results.append(combined_result)
            else:
                # Monta o resultado detalhado SEM consumo para planos não ativos
                combined_result = {
                    "iccid": iccid,
                    "orderNo": order_no,
                    "productName": order.get("productName"),
                    "status": order_status,
                    "validity_start_date": order.get("startDate"),
                    "validity_end_date": order.get("endDate"),
                    "daily_total_mb": "N/A",
                    "daily_usage_mb": "N/A",
                    "daily_remaining_mb": "N/A"
                }
                detailed_results.append(combined_result)

        return jsonify(detailed_results), 200

    except Exception as e:
        print("!!!!!!!!!! ERRO DETALHADO EM /get_iccid_history !!!!!!!!!!")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False)
