from flask import Flask, request, jsonify
import requests
import json
from datetime import datetime
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import traceback
import pytz

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
    # ... (código sem alterações) ...
    key = SECRET_KEY.encode('utf-8'); iv = VECTOR.encode('utf-8'); cipher = AES.new(key, AES.MODE_CBC, iv); padded_data = pad(data_str.encode('utf-8'), AES.block_size); encrypted_bytes = cipher.encrypt(padded_data); return ''.join([f"{chr(((b >> 4) & 0xF) + ord('a'))}{chr(((b & 0xF) + ord('a')))}" for b in encrypted_bytes])
def aes_decrypt(encrypted_hex):
    # ... (código sem alterações) ...
    key = SECRET_KEY.encode('utf-8'); iv = VECTOR.encode('utf-8'); encrypted_bytes = bytes([((ord(encrypted_hex[i]) - ord('a')) << 4) + (ord(encrypted_hex[i+1]) - ord('a')) for i in range(0, len(encrypted_hex), 2)]); cipher = AES.new(key, AES.MODE_CBC, iv); decrypted_padded_bytes = cipher.decrypt(encrypted_bytes); unpadded_bytes = unpad(decrypted_padded_bytes, AES.block_size); return unpadded_bytes.decode('utf-8')
def create_signature(service_name, request_time, encrypted_data):
    # ... (código sem alterações) ...
    raw_string = f"{ACCOUNT_ID}{service_name}{request_time}{encrypted_data}{API_VERSION}{SIGN_KEY}"; md5_hash = hashlib.md5(raw_string.encode('utf-8')).hexdigest(); return md5_hash

# --- Rota Completa para Detalhes do ICCID (ATUALIZADA) ---
@app.route('/get_full_iccid_details', methods=['POST'])
def get_full_iccid_details():
    try:
        sao_paulo_tz = pytz.timezone("America/Sao_Paulo")
        query_datetime_sp = datetime.now(sao_paulo_tz).strftime('%Y-%m-%d %H:%M:%S')
        request_body = request.get_json(); iccid = request_body.get("iccid")
        # ... (código de busca de pedidos, igual ao anterior) ...
        service_name_orders = "queryEsimOrderList"; endpoint_orders = "saleOrderApi/queryEsimOrderList"
        data_payload_orders = { "page": 1, "pageSize": 100, "iccid": iccid, "orderStatus": "", "lang": "en" }
        data_str = json.dumps(data_payload_orders); encrypted_data = aes_encrypt(data_str); request_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'); sign = create_signature(service_name_orders, request_time, encrypted_data)
        final_payload = { "accountId": ACCOUNT_ID, "serviceName": service_name_orders, "requestTime": request_time, "data": encrypted_data, "version": API_VERSION, "sign": sign }
        headers = {'Content-Type': 'application/json'}
        response_orders = requests.post(BASE_URL + endpoint_orders, data=json.dumps(final_payload), headers=headers, timeout=20); response_orders.raise_for_status(); response_orders_json = response_orders.json()
        if response_orders_json.get("code") != "0000": return jsonify({"error": "Failed to fetch orders for ICCID", "details": response_orders_json}), 400
        all_orders = json.loads(aes_decrypt(response_orders_json["data"]))
        if not all_orders: return jsonify([]), 200

        profile_info = {}
        first_order_no = all_orders[0].get("orderNo")
        if first_order_no:
            # ... (código de busca de perfil, igual ao anterior) ...
            service_name_profile = "getProfileInfo"; endpoint_profile = "saleSimApi/getProfileInfo"
            data_payload_profile = {"orderNo": first_order_no, "lang": "en"}
            data_str_profile = json.dumps(data_payload_profile); encrypted_data_profile = aes_encrypt(data_str_profile); request_time_profile = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'); sign_profile = create_signature(service_name_profile, request_time_profile, encrypted_data_profile)
            final_payload_profile = { "accountId": ACCOUNT_ID, "serviceName": service_name_profile, "requestTime": request_time_profile, "data": encrypted_data_profile, "version": API_VERSION, "sign": sign_profile }
            response_profile = requests.post(BASE_URL + endpoint_profile, data=json.dumps(final_payload_profile), headers=headers, timeout=20)
            if response_profile.status_code == 200 and response_profile.json().get("code") == "0000": profile_info = json.loads(aes_decrypt(response_profile.json().get("data", "")))

        detailed_results = []
        for order in all_orders:
            # ... (código de combinação de dados, agora com os campos de renovação) ...
            order_status = order.get("orderStatus"); order_no = order.get("orderNo"); start_date_sp, end_date_sp = "", ""
            try:
                utc_tz, date_format = pytz.utc, '%Y-%m-%d %H:%M:%S'
                if order.get("startDate"): start_date_sp = datetime.strptime(order.get("startDate"), date_format).replace(tzinfo=utc_tz).astimezone(sao_paulo_tz).strftime(date_format)
                if order.get("endDate"): end_date_sp = datetime.strptime(order.get("endDate"), date_format).replace(tzinfo=utc_tz).astimezone(sao_paulo_tz).strftime(date_format)
            except (ValueError, TypeError): pass
            usage_data = {}
            if order_status == "INUSE":
                # ... (código de busca de consumo, igual ao anterior) ...
                service_name_flow = "getEsimFlowByParams"; endpoint_flow = "saleSimApi/getEsimFlowByParams"; data_payload_flow = { "iccid": iccid, "orderNo": order_no, "lang": "en" }; data_str_flow = json.dumps(data_payload_flow); encrypted_data_flow = aes_encrypt(data_str_flow); request_time_flow = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'); sign_flow = create_signature(service_name_flow, request_time_flow, encrypted_data_flow); final_payload_flow = { "accountId": ACCOUNT_ID, "serviceName": service_name_flow, "requestTime": request_time_flow, "data": encrypted_data_flow, "version": API_VERSION, "sign": sign_flow }; response_flow = requests.post(BASE_URL + endpoint_flow, data=json.dumps(final_payload_flow), headers=headers, timeout=20)
                if response_flow.status_code == 200 and response_flow.json().get("code") == "0000": usage_data = json.loads(aes_decrypt(response_flow.json()["data"]))
            
            combined_result = {
                "data_consulta_sp": query_datetime_sp, "iccid": iccid, "eid": profile_info.get("eid"), "imsi": profile_info.get("imsi"),
                "profile_status": profile_info.get("state"), "install_device": profile_info.get("installDevice"), "install_time": profile_info.get("installTime"),
                "orderNo": order_no, "productName": order.get("productName"), "orderStatus": order_status,
                "validity_start_date_sp": start_date_sp, "validity_end_date_sp": end_date_sp,
                # ******** NOVOS CAMPOS ADICIONADOS AQUI ********
                "pode_renovar": profile_info.get("renewFlag"),
                "data_limite_renovacao": profile_info.get("renewExpirationTime"),
                # ******** FIM DA ADIÇÃO ********
                "daily_total_mb": usage_data.get("dataTotal", "N/A"), "daily_usage_mb": usage_data.get("qtaconsumption") or usage_data.get("dataUsage") or "N/A",
                "daily_remaining_mb": usage_data.get("dataResidual", "N/A")
            }
            detailed_results.append(combined_result)
        return jsonify(detailed_results), 200
    except Exception as e:
        print("!!!!!!!!!! ERRO DETALHADO EM /get_full_iccid_details !!!!!!!!!!"); traceback.print_exc(); return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False)
