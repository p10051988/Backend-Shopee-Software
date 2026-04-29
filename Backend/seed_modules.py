from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app_config import settings
from app_security import current_timestamp, new_nonce, sign_internal_request


BASE_URL = settings.backend_url
PATH = "/api/internal/upload_module"


def build_headers(body: dict) -> dict:
    if not settings.internal_api_secret:
        raise RuntimeError("INTERNAL_API_SECRET is not configured. Update .env before seeding modules.")

    timestamp = str(current_timestamp())
    nonce = new_nonce()
    return {
        "X-Internal-Key": "autoshopee-internal",
        "X-Internal-Timestamp": timestamp,
        "X-Internal-Nonce": nonce,
        "X-Internal-Signature": sign_internal_request(
            settings.internal_api_secret,
            "POST",
            PATH,
            timestamp,
            nonce,
            body,
        ),
    }


LOGIC_GET_HEADERS = r'''def _get_headers(self, referer_path="/portal") -> Dict:
        import sys
        if sys.gettrace():
            return {}

        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json',
            'Cookie': self.cookie_string,
            'X-CSRFToken': self.csrf_token,
            'Referer': f"{self.BASE_URL}{referer_path}",
            'Origin': self.BASE_URL,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'x-api-source': 'webchat',
            'x-shop-region': 'VN',
        }

        if 'SC_DFP' in self.cookies:
            headers['X-SPC-DF'] = self.cookies['SC_DFP']

        if self.fe_session:
            headers['sc-fe-session'] = self.fe_session
            headers['sc-fe-ver'] = self.fe_version

        return headers'''

LOGIC_ENSURE_FE = r'''def _ensure_fe_session(self):
        if self.fe_session:
            return

        try:
            headers = {
                'Cookie': self.cookie_string,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'vi-VN,vi;q=0.9',
                'Cache-Control': 'max-age=0',
                'x-api-source': 'pc',
                'af-ac-enc-dat': 'null'
            }
            res = self.session.get(self.BASE_URL, headers=headers, timeout=10)
            match_hash = re.search(r'sellerCenterFeSessionHash\s*=\s*["\']([^"\']+)["\']', res.text)
            if match_hash:
                self.fe_session = match_hash.group(1)
        except Exception:
            pass'''

LOGIC_SAFE_JSON = r'''def _safe_json(self, resp) -> Dict:
        text = resp.text.strip()
        if text.startswith("null{"):
            text = text[4:]
        elif text.startswith("null"):
             text = text[4:].strip()

        if not text:
            return {"code": -1, "message": "Empty response"}

        try:
            return json.loads(text)
        except Exception as e:
            first_brace = text.find('{')
            if first_brace > 0:
                try:
                    return json.loads(text[first_brace:])
                except Exception:
                    pass
            return {"code": -1, "message": f"JSON Error: {str(e)}"}'''

LOGIC_CHAT_LOGIN = r'''def login_webchat(self):
        import sys
        if sys.gettrace():
            return False

        url = f"{self.BASE_URL}/webchat/api/coreapi/v1.2/login"
        headers = self._get_headers(referer_path="/new-webchat/conversations")
        spc_u = self.cookies.get('SPC_U')
        params = {'_v': '9.0.5', 'csrf_token': self.csrf_token}
        if spc_u:
            params['_uid'] = f"0-{spc_u}"

        try:
            res = self.session.get(url, headers=headers, params=params, timeout=10)
            data = res.json()
            return isinstance(data, dict) and data.get('code') == 0
        except Exception:
            return False'''

LOGIC_GET_CONVERSATION_LIST = r'''def get_conversation_list(self, limit=20, offset=0):
        from urllib.parse import unquote

        fragment_cfg = {"limit": 20, "retries": 3}
        try:
            from utils.remote_loader import RemoteLoader

            fragment = RemoteLoader.ask_soul_fragment("chat_limit", "conversation_list")
            if isinstance(fragment, dict):
                fragment_cfg.update(fragment)
        except Exception:
            pass

        safe_limit = max(1, min(int(limit or 20), int(fragment_cfg.get("limit", 20) or 20)))
        safe_offset = max(0, int(offset or 0))
        retries = max(1, min(int(fragment_cfg.get("retries", 3) or 3), 4))

        url = f"{self.BASE_URL}/webchat/api/v1.2/conversations"
        headers = self._get_headers(referer_path="/new-webchat/conversations")

        if self.fe_session:
            headers["sc-fe-session"] = self.fe_session
        if getattr(self, "jwt_token", None):
            headers["Authorization"] = f"Bearer {self.jwt_token}"

        csrf_token_val = self.csrf_token
        if self.cookies.get("CTOKEN"):
            try:
                csrf_token_val = unquote(self.cookies.get("CTOKEN"))
            except Exception:
                pass

        params = {
            "direction": "older",
            "limit": safe_limit,
            "offset": safe_offset,
            "on_message_received": "true",
            "biz_id": "0",
            "x-shop-region": "VN",
            "_api_source": "webchat",
            "_v": "9.0.5",
            "csrf_token": csrf_token_val,
        }

        spc_cds_chat = self.cookies.get("SPC_CDS_CHAT")
        if spc_cds_chat:
            params["SPC_CDS_CHAT"] = spc_cds_chat

        spc_u = self.cookies.get("SPC_U")
        if spc_u:
            params["_uid"] = f"0-{spc_u}"

        for attempt in range(retries):
            try:
                res = self.session.get(url, headers=headers, params=params, timeout=10)
                if res.status_code != 200:
                    debug_info = f"cookies={len(list(self.session.cookies.keys()))}|fe={getattr(self, 'fe_session', 'N/A')}"
                    return {"code": res.status_code, "message": f"{res.text} | {debug_info}"}

                data = res.json()
                if isinstance(data, list):
                    return {"code": 0, "data": {"conversations": data}}
                return data
            except Exception as exc:
                if attempt >= retries - 1:
                    return {"code": -1, "message": str(exc)}
                time.sleep(1)

        return {"code": -1, "message": "Conversation fetch failed"}'''

LOGIC_GET_CHAT_MESSAGES = r'''def get_chat_messages(self, conversation_id, offset=0, limit=20):
        from urllib.parse import unquote

        fragment_cfg = {"limit": 20}
        try:
            from utils.remote_loader import RemoteLoader

            fragment = RemoteLoader.ask_soul_fragment("chat_limit", "message_list")
            if isinstance(fragment, dict):
                fragment_cfg.update(fragment)
        except Exception:
            pass

        safe_limit = max(1, min(int(limit or 20), int(fragment_cfg.get("limit", 20) or 20)))
        safe_offset = max(0, int(offset or 0))

        url = f"{self.BASE_URL}/webchat/api/v1.2/conversations/{conversation_id}/messages"
        headers = self._get_headers(referer_path="/new-webchat/conversations")
        if getattr(self, "jwt_token", None):
            headers["Authorization"] = f"Bearer {self.jwt_token}"

        params = {
            "direction": "older",
            "limit": safe_limit,
            "offset": safe_offset,
            "shop_id": self.cookies.get("shop_id", "0"),
            "x-shop-region": "VN",
            "_api_source": "webchat",
            "_v": "9.0.5",
            "csrf_token": self.csrf_token,
            "on_message_received": "true",
            "biz_id": "0",
        }

        spc_cds_chat = self.cookies.get("SPC_CDS_CHAT")
        if spc_cds_chat:
            params["SPC_CDS_CHAT"] = spc_cds_chat

        spc_u = self.cookies.get("SPC_U")
        if spc_u:
            params["_uid"] = f"0-{spc_u}"

        if self.cookies.get("CTOKEN"):
            try:
                params["csrf_token"] = unquote(self.cookies.get("CTOKEN"))
            except Exception:
                pass

        try:
            res = self.session.get(url, headers=headers, params=params, timeout=10)
            data = res.json()
            if isinstance(data, list):
                return {"code": 0, "data": {"messages": data}}
            return data
        except Exception as exc:
            return {"code": -1, "message": str(exc)}'''

LOGIC_SEND_MESSAGE = r'''def send_message(self, conversation_id, to_id, content, msg_type="text"):
        import uuid

        payload = {
            "request_id": str(uuid.uuid4()),
            "to_id": int(to_id),
            "type": msg_type,
            "content": {"text": content} if msg_type == "text" else content,
            "conversation_id": conversation_id,
        }

        headers = self._get_headers(referer_path="/new-webchat/conversations")
        if getattr(self, "jwt_token", None):
            headers["Authorization"] = f"Bearer {self.jwt_token}"

        try:
            url = f"{self.BASE_URL}/webchat/api/v1.2/messages"
            return self.session.post(url, headers=headers, json=payload, timeout=10).json()
        except Exception as exc:
            return {"code": -1, "message": str(exc)}'''

LOGIC_GET_ORDER_LIST = r'''def get_order_list_impl(cookies, status="ALL", page=1, page_size=20):
    import requests

    try:
        status_map = {
            "ALL": 100,
            "UNPAID": 200,
            "TO_SHIP": 300,
            "SHIPPING": 400,
            "COMPLETED": 500,
            "CANCELLED": 100,
            "TO_RETURN": 100
        }

        tab_id = status_map.get(status, 100)
        cookie_string = ""
        csrf_token = ""
        spc_cds = ""
        fe_session = ""

        if isinstance(cookies, dict):
             cookie_string = '; '.join([f"{k}={v}" for k, v in cookies.items()])
             csrf_token = cookies.get('csrftoken', '') or cookies.get('CTOKEN', '')
             spc_cds = cookies.get('SPC_CDS', '')
             fe_session = cookies.get('sellerCenterFeSessionHash', '')
        else:
             cookie_string = cookies
             if "csrftoken=" in cookies:
                 csrf_token = cookies.split("csrftoken=")[1].split(";")[0]

        headers = {
            'Authority': 'banhang.shopee.vn',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json',
            'Cookie': cookie_string,
            'X-Csrftoken': csrf_token,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Referer': 'https://banhang.shopee.vn/portal/sale/order',
            'Origin': 'https://banhang.shopee.vn'
        }

        if spc_cds:
            headers['SPC_CDS'] = spc_cds
            headers['SPC_CDS_CHAT'] = spc_cds
        if fe_session:
             headers['sc-fe-session'] = fe_session
             headers['sc-fe-ver'] = '21.131261'

        url_index = "https://banhang.shopee.vn/api/v3/order/search_order_list_index"
        if spc_cds:
            url_index += f"?SPC_CDS={spc_cds}&SPC_CDS_VER=2"

        payload_index = {
            "order_list_tab": tab_id,
            "entity_type": 1,
            "pagination": {"from_page_number": page, "page_number": page, "page_size": page_size},
            "filter": {"fulfillment_type": 0, "is_drop_off": 0, "fulfillment_source": 0, "action_filter": 0},
            "sort": {"sort_type": 3, "ascending": False}
        }

        response = requests.post(url_index, headers=headers, json=payload_index, timeout=15)
        if response.status_code != 200:
            return {"success": False, "error": f"HTTP Error Index: {response.status_code}"}

        data = response.json()
        if data.get('code') != 0:
             return {"success": False, "error": f"API Error: {data.get('message')}"}

        data_data = data.get('data', {})
        order_list_index = data_data.get('index_list', []) or data_data.get('order_list', [])
        total_count = data_data.get('total_count', 0) or data_data.get('total', 0)
        if not order_list_index:
            return {"success": True, "data": [], "total": total_count}

        url_card = "https://banhang.shopee.vn/api/v3/order/get_order_list_card_list"
        if spc_cds:
            url_card += f"?SPC_CDS={spc_cds}&SPC_CDS_VER=2"

        cleaned_params = [{"order_id": item.get("order_id"), "shop_id": item.get("shop_id"), "region_id": item.get("region_id", "VN")} for item in order_list_index]
        shop_id_map = {item.get("order_id"): item.get("shop_id") for item in order_list_index}
        all_orders = []

        for i in range(0, len(cleaned_params), 5):
            payload_card = {
                "order_list_tab": tab_id,
                "need_count_down_desc": False,
                "order_param_list": cleaned_params[i:i + 5]
            }
            resp_card = requests.post(url_card, headers=headers, json=payload_card, timeout=15)
            if resp_card.status_code == 200:
                data_card = resp_card.json()
                if data_card.get('code') == 0:
                    orders_chunk = data_card.get('data', {}).get('card_list', []) or data_card.get('data', {}).get('order_list', [])
                    for order in orders_chunk:
                        oid = order.get('order_id') or order.get('order_ext_info', {}).get('order_id')
                        if oid and oid in shop_id_map:
                            order['shop_id'] = shop_id_map[oid]
                    all_orders.extend(orders_chunk)

        return {"success": True, "data": all_orders or order_list_index, "total": total_count}
    except Exception as e:
        return {"success": False, "error": str(e)}'''

LOGIC_CREATE_PRODUCT = r'''def create_product_complete(
        self,
        name: str,
        description: str,
        category_id: int,
        price: int,
        stock: int,
        weight: int,
        image_paths: List[str],
        **kwargs
    ) -> Dict:
        image_ids = self.upload_multiple_images(image_paths)
        if not image_ids:
            return {"error": "Không upload được ảnh nào"}

        product_data = {
            "name": name,
            "description": description,
            "category_id": category_id,
            "images": image_ids,
            "price": price,
            "stock": stock,
            "weight": weight,
            "brand": kwargs.get('brand', {"brand_id": 0, "original_brand_name": "No Brand"}),
            "item_sku": kwargs.get('sku', ''),
            "attributes": kwargs.get('attributes', []),
            "dimension": kwargs.get('dimension', {"width": 10, "height": 15, "length": 5}),
            "pre_order": {"is_pre_order": False, "days_to_ship": kwargs.get('days_to_ship', 2)},
            "condition": 1,
            "status": 1,
            "logistic": {"enabled": True, "is_free": False, "size_id": 0},
            "wholesales": [],
            "video": kwargs.get('video', None),
            "unfilled_gtin": True
        }
        return self.add_product(product_data)'''

LOGIC_GET_PRODUCT_LIST = r'''def get_product_list(self, list_type='live_all', page_number=1, page_size=12, keyword=None, cursor=None) -> Dict:
        limit_cfg = {"limit": 20}
        try:
            from utils.remote_loader import RemoteLoader

            fragment = RemoteLoader.ask_soul_fragment("product_limit", str(list_type))
            if isinstance(fragment, dict):
                limit_cfg.update(fragment)
        except Exception:
            pass

        safe_page = max(1, int(page_number or 1))
        safe_size = max(1, min(int(page_size or 12), int(limit_cfg.get("limit", 20) or 20)))
        params = {
            "list_type": list_type,
            "page_number": safe_page,
            "page_size": safe_size,
            "offset": (safe_page - 1) * safe_size,
            "limit": safe_size,
            "SPC_CDS": self.session_id,
            "SPC_CDS_VER": "2",
        }

        if cursor:
            params["cursor"] = cursor
        if keyword:
            params["keyword"] = keyword

        try:
            url = f"{self.BASE_URL}/api/v3/opt/mpsku/list/v2/search_product_list"
            res = self.session.get(url, headers=self._get_headers(), params=params, timeout=10)
            return res.json()
        except Exception as exc:
            return {"code": -1, "message": str(exc)}'''

LOGIC_UPDATE_PRODUCT = r'''def update_product(self, product_id: int, data: Dict) -> Dict:
        if not isinstance(data, dict):
            return {"code": -1, "message": "Invalid update payload"}

        url = f"{self.BASE_URL}/api/v3/product/update_product"
        params = {
            "SPC_CDS": self.session_id,
            "SPC_CDS_VER": "2",
        }
        payload = {
            "id": product_id,
            **data,
        }

        try:
            res = self.session.post(
                url,
                headers=self._get_headers(f"/portal/product/{product_id}"),
                params=params,
                json=[payload],
                timeout=10,
            )
            return res.json()
        except Exception as exc:
            return {"code": -1, "message": str(exc)}'''

LOGIC_GET_SHOP_RATING_LIST = r'''def get_shop_rating_list(self, filter_type='all', page_number=1, page_size=10) -> Dict:
        fragment_cfg = {"limit": 20}
        try:
            from utils.remote_loader import RemoteLoader

            fragment = RemoteLoader.ask_soul_fragment("rating_limit", str(filter_type))
            if isinstance(fragment, dict):
                fragment_cfg.update(fragment)
        except Exception:
            pass

        qt_type = 0
        if filter_type == "to_reply":
            qt_type = 1
        elif filter_type == "replied":
            qt_type = 2

        safe_page = max(1, int(page_number or 1))
        safe_size = max(1, min(int(page_size or 10), int(fragment_cfg.get("limit", 20) or 20)))
        params = {
            "vpc_cds": self.session_id,
            "SPC_CDS": self.session_id,
            "SPC_CDS_VER": "2",
            "page_number": safe_page,
            "page_size": safe_size,
            "reply_status": qt_type,
        }

        def make_url(path):
            if not path:
                return ""
            if str(path).startswith("http"):
                return path
            return f"https://down-vn.img.susercontent.com/file/{path}"

        try:
            url = f"{self.BASE_URL}/api/v3/settings/search_shop_rating_comments_new/"
            headers = self._get_headers(referer_path="/portal/settings/shop/rating")
            data = requests.get(url, headers=headers, params=params, timeout=10).json()
            if data.get("code") != 0:
                return data

            raw_list = data.get("data", {}).get("list", [])
            clean_list = []
            for item in raw_list:
                clean_list.append(
                    {
                        "rating_id": item.get("comment_id"),
                        "order_id": item.get("order_id"),
                        "order_sn": item.get("order_sn"),
                        "buyer_username": item.get("buyer_username") or item.get("user_name"),
                        "product_name": item.get("product_name"),
                        "product_image": make_url(item.get("product_cover")),
                        "model_name": item.get("model_name"),
                        "rating_star": item.get("rating_star"),
                        "comment": item.get("comment"),
                        "rating_time": item.get("ctime"),
                        "tags": item.get("tags", []),
                        "images": [make_url(img) for img in item.get("images", [])],
                        "reply": item.get("reply"),
                        "can_reply": item.get("editable") == True or item.get("reply") is None,
                    }
                )

            return {
                "code": 0,
                "data": {
                    "list": clean_list,
                    "total": data.get("data", {}).get("total", 0),
                    "counts": data.get("data", {}).get("counts", {}),
                },
            }
        except Exception as exc:
            return {"code": -1, "message": str(exc)}'''

LOGIC_REPLY_RATING = r'''def reply_rating(self, rating_id: int, order_id: int, reply_text: str) -> Dict:
        payload = {
            "order_id": order_id,
            "comment_id": rating_id,
            "comment": str(reply_text or "").strip(),
        }
        params = {
            "SPC_CDS": self.session_id,
            "SPC_CDS_VER": "2",
        }

        try:
            url = f"{self.BASE_URL}/api/v3/settings/reply_shop_rating/"
            headers = self._get_headers(referer_path="/portal/settings/shop/rating")
            return requests.post(url, headers=headers, params=params, json=payload, timeout=10).json()
        except Exception as exc:
            return {"code": -1, "message": str(exc)}'''


def upload(name, code):
    payload = {
        "name": name,
        "version": "2.0.0",
        "code_content": code,
    }
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    headers = build_headers(payload)
    headers["Content-Type"] = "application/json"
    try:
        request = urllib.request.Request(
            f"{BASE_URL}{PATH}",
            data=body,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read().decode("utf-8", errors="replace")
            print(f"Success: {name}")
            if raw:
                print(f"  {raw[:160]}")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        print(f"Failed: {name} -> {e.code} {detail}")
    except Exception as e:
        print(f"Error: {name} -> {e}")


if __name__ == "__main__":
    upload("_get_headers", LOGIC_GET_HEADERS)
    upload("_ensure_fe_session", LOGIC_ENSURE_FE)
    upload("_safe_json", LOGIC_SAFE_JSON)
    upload("login_webchat", LOGIC_CHAT_LOGIN)
    upload("get_conversation_list", LOGIC_GET_CONVERSATION_LIST)
    upload("get_chat_messages", LOGIC_GET_CHAT_MESSAGES)
    upload("send_message", LOGIC_SEND_MESSAGE)
    upload("get_order_list_impl", LOGIC_GET_ORDER_LIST)
    upload("create_product_complete", LOGIC_CREATE_PRODUCT)
    upload("get_product_list", LOGIC_GET_PRODUCT_LIST)
    upload("update_product", LOGIC_UPDATE_PRODUCT)
    upload("get_shop_rating_list", LOGIC_GET_SHOP_RATING_LIST)
    upload("reply_rating", LOGIC_REPLY_RATING)
