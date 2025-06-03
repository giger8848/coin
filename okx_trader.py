#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import time
import logging
import ccxt
import pandas as pd
from datetime import datetime, timedelta
import sys
import traceback
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from tkinter import filedialog
import queue
import hashlib
import platform
import uuid
import webbrowser
from urllib.parse import urlparse, parse_qs
import requests
# from google.auth.transport.requests import Request
# from google.oauth2.credentials import Credentials
# from google_auth_oauthlib.flow import Flow
import gspread
import base64
from cryptography.fernet import Fernet

# 한글 인코딩 설정
if sys.platform.startswith('win'):
    try:
        import io
        if hasattr(sys.stdout, 'buffer'):
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    except:
        pass

# 로깅 설정
try:
    logging.basicConfig(
        filename='log.txt',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        encoding='utf-8'
    )
except TypeError:
    logging.basicConfig(
        filename='log.txt',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

logger = logging.getLogger()

# class GoogleSheetsAuth:
#     """Google Sheets 기반 사용자 인증"""
    
#     def __init__(self):
#         # 암호화된 OAuth 설정 (여기에 실제 값을 넣으세요)
#         self.encrypted_client_id = "gAAAAABoO-ylBzalvvVR_wcyq5XcRACZ12IoOzhvuA-Xr1ZC1_R948X3IsdsGrPZZ1E44PkXAKPI1w7FODBu6l6tikIx3bLY7ZMsQPYGAEOuVBKdhU5V2MHE9iw6tA5NpDaaZ9RqPQouhhwHcD3rNL4kY_qqPubKozQg_xA9sgeV29H2QZDwMjo="  # 실제 암호화된 Client ID
#         self.encrypted_client_secret = "gAAAAABoO-ylIHkEayh5mQOO2-37Ug4CTiy_tVj-XlbvWnHxo2TiHVA5trGVJxC0F4DTcKlNodv-90FiOWPCwA5EbmO2cD9qT7cw2kP5VyGSI12nTYqX6eVmdKDxzQY6twAQUisKyKjA"  # 실제 암호화된 Client Secret
        
#         self.load_oauth_config()
#         self.spreadsheet_id = "1IRHmVTt1nkYcu2cJcQ1LOWVbfYIXjpbWF3owQMiEDZk"
#         self.worksheet_name = "authorized_users"
#         self.redirect_uri = "http://localhost:8080/callback"
#         self.scopes = [
#             'https://www.googleapis.com/auth/userinfo.email',
#             'https://www.googleapis.com/auth/userinfo.profile', 
#             'openid',
#             'https://www.googleapis.com/auth/spreadsheets.readonly'
#         ]
#         self.cache_file = "auth_cache.json"
#         self.cache_duration = 3600
#         self.user_info = None
#         self.credentials = None

#     def generate_key(self):
#         """고정된 암호화 키 생성"""
#         # 더 안정적인 고정 키 사용
#         fixed_key = "okx-trader-2024-secure-key-fixed-string"
#         key_data = hashlib.sha256(fixed_key.encode()).digest()
#         return base64.urlsafe_b64encode(key_data)

#     def decrypt_config(self, encrypted_data):
#         """암호화된 설정 복호화"""
#         try:
#             # 기본값인지 확인
#             if encrypted_data in ["gAAAAABh...", ""]:
#                 return ""
                
#             key = self.generate_key()
#             f = Fernet(key)
#             decrypted = f.decrypt(encrypted_data.encode()).decode()
            
#             # 복호화 성공 시 로그
#             logger.info("OAuth 설정 복호화 성공")
#             return decrypted
            
#         except Exception as e:
#             logger.error(f"OAuth 설정 복호화 실패: {str(e)}")
#             return ""

#     def load_oauth_config(self):
#         """OAuth 설정 로드 (암호화된 데이터 사용)"""
#         try:
#             # 디버깅용 로그 추가
#             logger.info(f"암호화된 Client ID 길이: {len(self.encrypted_client_id)}")
#             logger.info(f"암호화된 Client Secret 길이: {len(self.encrypted_client_secret)}")
            
#             # 암호화된 설정 복호화
#             self.client_id = self.decrypt_config(self.encrypted_client_id)
#             self.client_secret = self.decrypt_config(self.encrypted_client_secret)
            
#             # 디버깅용 로그 추가
#             logger.info(f"복호화된 Client ID: {self.client_id[:20] if self.client_id else 'None'}...")
#             logger.info(f"복호화된 Client Secret: {self.client_secret[:10] if self.client_secret else 'None'}...")
            
#             # 복호화 실패 시 오류 처리
#             if not self.client_id or not self.client_secret:
#                 logger.error("암호화된 OAuth 설정 복호화 실패 - 설정이 올바르지 않습니다")
#                 self.client_id = ""
#                 self.client_secret = ""
#             else:
#                 logger.info("암호화된 OAuth 설정 로드 성공")
                
#         except Exception as e:
#             logger.error(f"OAuth 설정 로드 실패: {str(e)}")
#             self.client_id = ""
#             self.client_secret = ""

#     def load_from_file(self):
#         """파일에서 OAuth 설정 로드 (백업용)"""
#         config_file = "oauth_config.json"
        
#         try:
#             if os.path.exists(config_file):
#                 with open(config_file, 'r', encoding='utf-8') as f:
#                     config = json.load(f)
#                 self.client_id = config.get('client_id', '')
#                 self.client_secret = config.get('client_secret', '')
#                 logger.info("OAuth 설정을 파일에서 로드했습니다.")
#             else:
#                 self.client_id = ""
#                 self.client_secret = ""
#                 self.create_sample_config(config_file)
#                 logger.warning("OAuth 설정 파일이 없어 기본 템플릿을 생성했습니다.")
#         except Exception as e:
#             logger.error(f"파일에서 OAuth 설정 로드 실패: {str(e)}")
#             self.client_id = ""
#             self.client_secret = ""

#     def create_sample_config(self, config_file):
#         """샘플 OAuth 설정 파일 생성"""
#         sample_config = {
#             "client_id": "YOUR_CLIENT_ID.apps.googleusercontent.com",
#             "client_secret": "YOUR_CLIENT_SECRET",
#             "instructions": {
#                 "1": "Google Cloud Console에서 OAuth 2.0 클라이언트 ID 생성",
#                 "2": "애플리케이션 타입: Web application 선택",
#                 "3": "승인된 리디렉션 URI에 http://localhost:8080/callback 추가",
#                 "4": "생성된 Client ID와 Client Secret을 위에 입력",
#                 "5": "이 파일을 저장 후 프로그램 재시작"
#             }
#         }
        
#         try:
#             with open(config_file, 'w', encoding='utf-8') as f:
#                 json.dump(sample_config, f, indent=2, ensure_ascii=False)
#             logger.info(f"샘플 OAuth 설정 파일을 생성했습니다: {config_file}")
#         except Exception as e:
#             logger.error(f"샘플 설정 파일 생성 실패: {str(e)}")

#     def validate_oauth_config(self):
#         """OAuth 설정 유효성 검사"""
#         if not self.client_id or not self.client_secret:
#             return False, "Client ID 또는 Client Secret이 설정되지 않았습니다."
        
#         if not self.client_id.endswith('.apps.googleusercontent.com'):
#             return False, "Client ID 형식이 올바르지 않습니다."
        
#         if self.client_id == 'YOUR_CLIENT_ID.apps.googleusercontent.com' or self.client_secret == 'YOUR_CLIENT_SECRET':
#             return False, "OAuth 설정이 기본값으로 되어 있습니다. oauth_config.json을 수정해주세요."
        
#         return True, "OAuth 설정이 유효합니다."

#     def check_authorization(self):
#         """메인 인증 확인 함수"""
#         try:
#             logger.info("=== 인증 과정 시작 ===")
            
#             is_valid, message = self.validate_oauth_config()
#             if not is_valid:
#                 logger.error(f"OAuth 설정 오류: {message}")
#                 messagebox.showerror("OAuth 설정 오류", 
#                     f"{message}\n\n"
#                     f"oauth_config.json 파일을 확인하고 올바른 Client ID와 Client Secret을 설정해주세요.")
#                 return False
            
#             if self.load_cached_auth():
#                 logger.info("캐시된 인증 정보로 로그인 성공")
#                 return True
            
#             if self.perform_google_auth():
#                 if self.check_user_in_sheets():
#                     self.save_auth_cache()
#                     logger.info(f"사용자 인증 성공: {self.user_info['email']}")
#                     return True
#                 else:
#                     self.show_unauthorized_message()
#                     return False
            
#             return False
            
#         except Exception as e:
#             logger.error(f"인증 오류: {str(e)}")
#             messagebox.showerror("인증 오류", f"인증 과정에서 오류가 발생했습니다:\n{str(e)}")
#             return False

#     def load_cached_auth(self):
#         """캐시된 인증 정보 로드"""
#         try:
#             if not os.path.exists(self.cache_file):
#                 return False
            
#             with open(self.cache_file, 'r', encoding='utf-8') as f:
#                 cache_data = json.load(f)
            
#             cache_time = datetime.fromisoformat(cache_data['timestamp'])
#             if datetime.now() - cache_time > timedelta(seconds=self.cache_duration):
#                 return False
            
#             if cache_data.get('machine_id') != self.get_machine_id():
#                 return False
            
#             self.user_info = cache_data['user_info']
#             return True
            
#         except Exception as e:
#             logger.warning(f"캐시 로드 실패: {str(e)}")
#             return False

#     def perform_google_auth(self):
#         """Google OAuth 인증"""
#         try:
#             flow = Flow.from_client_config(
#                 {
#                     "web": {
#                         "client_id": self.client_id,
#                         "client_secret": self.client_secret,
#                         "auth_uri": "https://accounts.google.com/o/oauth2/auth",
#                         "token_uri": "https://oauth2.googleapis.com/token",
#                         "redirect_uris": [self.redirect_uri]
#                     }
#                 },
#                 scopes=self.scopes
#             )
#             flow.redirect_uri = self.redirect_uri
            
#             auth_url, state = flow.authorization_url(
#                 access_type='offline',
#                 include_granted_scopes='false',
#                 prompt='select_account'
#             )
            
#             messagebox.showinfo("Google 인증", 
#                 "브라우저에서 Google 로그인을 완료해주세요.\n"
#                 "로그인 후 자동으로 프로그램으로 돌아옵니다.")
            
#             webbrowser.open(auth_url)
#             auth_code = self.wait_for_callback()
            
#             if auth_code:
#                 try:
#                     flow.fetch_token(code=auth_code)
#                     self.credentials = flow.credentials
#                     return self.fetch_user_info()
#                 except Exception as token_error:
#                     if hasattr(flow, 'credentials') and flow.credentials:
#                         self.credentials = flow.credentials
#                         return self.fetch_user_info()
#                     else:
#                         raise token_error
#             return False
            
#         except Exception as e:
#             logger.error(f"Google 인증 실패: {str(e)}")
#             messagebox.showerror("Google 인증 실패", f"Google 인증 중 오류가 발생했습니다:\n{str(e)}")
#             return False

#     def wait_for_callback(self):
#         """OAuth 콜백 대기"""
#         import socket
#         from http.server import HTTPServer, BaseHTTPRequestHandler
        
#         auth_code = None
#         server_error = None
        
#         class CallbackHandler(BaseHTTPRequestHandler):
#             def do_GET(self):
#                 nonlocal auth_code, server_error
#                 try:
#                     parsed_url = urlparse(self.path)
#                     query_params = parse_qs(parsed_url.query)
                    
#                     if 'code' in query_params:
#                         auth_code = query_params['code'][0]
                        
#                         self.send_response(200)
#                         self.send_header('Content-type', 'text/html; charset=utf-8')
#                         self.end_headers()
                        
#                         html = """
#                         <html>
#                         <head><title>인증 완료</title><meta charset="utf-8"></head>
#                         <body style="font-family: Arial; text-align: center; padding: 50px;">
#                             <h1>인증이 완료되었습니다!</h1>
#                             <p>이제 이 창을 닫고 프로그램으로 돌아가세요.</p>
#                         </body>
#                         </html>
#                         """.encode('utf-8')
                        
#                         self.wfile.write(html)
                    
#                 except Exception as e:
#                     server_error = str(e)
                
#             def log_message(self, format, *args):
#                 pass
        
#         try:
#             server = HTTPServer(('localhost', 8080), CallbackHandler)
#             server.timeout = 120
#             server.handle_request()
            
#             if server_error:
#                 raise Exception(server_error)
            
#             return auth_code
            
#         except Exception as e:
#             logger.error(f"콜백 서버 오류: {str(e)}")
#             return None

#     def fetch_user_info(self):
#         """사용자 정보 조회"""
#         try:
#             if not self.credentials:
#                 return False
            
#             response = requests.get(
#                 'https://www.googleapis.com/oauth2/v2/userinfo',
#                 headers={'Authorization': f'Bearer {self.credentials.token}'},
#                 timeout=10
#             )
            
#             if response.status_code == 200:
#                 self.user_info = response.json()
#                 return True
#             return False
            
#         except Exception as e:
#             logger.error(f"사용자 정보 조회 실패: {str(e)}")
#             return False

#     def check_user_in_sheets(self):
#         """Google Sheets에서 사용자 권한 확인"""
#         try:
#             if not self.user_info or not self.credentials:
#                 return False
            
#             user_email = self.user_info.get('email', '').lower()
#             gc = gspread.authorize(self.credentials)
#             spreadsheet = gc.open_by_key(self.spreadsheet_id)
#             worksheet = spreadsheet.worksheet(self.worksheet_name)
#             records = worksheet.get_all_records()
            
#             for record in records:
#                 sheet_email = record.get('email', '').lower()
#                 status = record.get('status', '').lower()
#                 expires_at = record.get('expires_at', '')
                
#                 if sheet_email == user_email and status == 'active':
#                     if expires_at:
#                         try:
#                             expiry_date = datetime.strptime(expires_at, '%Y-%m-%d')
#                             if datetime.now() > expiry_date:
#                                 return False
#                         except ValueError:
#                             pass
#                     return True
            
#             return False
            
#         except Exception as e:
#             logger.error(f"Google Sheets 확인 오류: {str(e)}")
#             return False

#     def get_machine_id(self):
#         """머신 고유 ID 생성"""
#         try:
#             machine_info = f"{platform.node()}-{uuid.getnode()}-{platform.machine()}"
#             return hashlib.sha256(machine_info.encode()).hexdigest()[:16]
#         except:
#             return "unknown"

#     def save_auth_cache(self):
#         """인증 정보 캐시 저장"""
#         try:
#             cache_data = {
#                 'user_info': self.user_info,
#                 'timestamp': datetime.now().isoformat(),
#                 'machine_id': self.get_machine_id()
#             }
            
#             with open(self.cache_file, 'w', encoding='utf-8') as f:
#                 json.dump(cache_data, f, indent=2, ensure_ascii=False)
                
#         except Exception as e:
#             logger.warning(f"캐시 저장 실패: {str(e)}")

#     def show_unauthorized_message(self):
#         """권한 없음 메시지"""
#         user_email = self.user_info.get('email', '알 수 없음') if self.user_info else '알 수 없음'
#         messagebox.showerror("접근 권한 없음", 
#             f"접근 권한이 없습니다\n\n사용자: {user_email}\n\n"
#             f"이 프로그램을 사용하려면 관리자의 승인이 필요합니다.")

#     def get_user_info(self):
#         return self.user_info

#     def logout(self):
#         try:
#             if os.path.exists(self.cache_file):
#                 os.remove(self.cache_file)
#             self.user_info = None
#             self.credentials = None
#             return True
#         except:
#             return False

class MultiSymbolAutoTrader:
    """멀티 심볼 자동매매 엔진"""
    
    def __init__(self, settings, log_queue=None):
        self.settings = settings
        self.log_queue = log_queue
        self.exchange = self.initialize_exchange()
        self.symbol_states = {}
        
        # 자본 사용 비율에 따른 레벨 설정 계산
        self.calculate_levels()
        
        for symbol in self.settings['symbols']:
            if symbol.strip():  # 빈 문자열이 아닌 경우만
                self.symbol_states[symbol] = {
                    'balance': 0,
                    'current_position': None,
                    'current_orders': [],
                    'order_level': 0,
                    'last_close_time': None,
                    'is_first_entry': True,
                    'is_active': True,
                    'just_entered': False,
                    'tp_order_id': None,
                    'current_tp_price': None,
                    'current_tp_type': None,  # 'profit' or 'donchian'
                    'donchian_data': [],  # 80시간 고저 데이터
                    'reached_target_level': False,  # 목표 차수 도달 여부
                    'last_donchian_update': None,  # 마지막 돈치안 업데이트 시간
                    'cached_donchian_basis': None,  # 캐시된 돈치안 베이시스
                    'cumulative_amounts': {}  # 누적 수량 테이블
                }
        
        self.set_leverages()
        self.should_stop = False

    def calculate_levels(self):
        """자본 사용 비율에 따른 레벨 설정 계산"""
        base_levels = {
            '1': {'distance': 0, 'ratio': 5.0},
            '2': {'distance': 1.5, 'ratio': 5.0},
            '3': {'distance': 3.0, 'ratio': 7.5},
            '4': {'distance': 5.0, 'ratio': 10.0},
            '5': {'distance': 8.0, 'ratio': 12.5},
            '6': {'distance': 12.0, 'ratio': 15.0},
            '7': {'distance': 17.0, 'ratio': 20.0},
            '8': {'distance': 23.0, 'ratio': 25.0},
            '9': {'distance': 30.0, 'ratio': 30.0},
            '10': {'distance': 38.0, 'ratio': 40.0}
        }
        
        # 기본 총 비율 (170%)
        base_total_ratio = sum(level['ratio'] for level in base_levels.values())
        
        # 사용자 설정 비율
        user_ratio = self.settings.get('capital_usage_ratio', 170)
        multiplier = user_ratio / base_total_ratio
        
        # 계산된 레벨 설정
        self.settings['levels'] = {}
        for level, config in base_levels.items():
            self.settings['levels'][level] = {
                'distance': config['distance'],
                'ratio': config['ratio'] * multiplier
            }

    def log(self, message):
        """로그 메시지 전송"""
        logger.info(message)
        if self.log_queue:
            self.log_queue.put(message)
        print(message)

    def initialize_exchange(self):
        """거래소 API 초기화"""
        try:
            exchange = ccxt.okx({
                'apiKey': self.settings['api_key'],
                'secret': self.settings['secret_key'],
                'password': self.settings['password'],
                'options': {'defaultType': 'swap'},
                'enableRateLimit': True
            })

            exchange.load_time_difference()
            self.check_and_set_position_mode(exchange)
            self.log("거래소 API 연결 성공")
            return exchange
        except Exception as e:
            error_msg = f"거래소 API 연결 오류: {str(e)}"
            self.log(error_msg)
            raise Exception(error_msg)

    def check_and_set_position_mode(self, exchange):
        """포지션 모드 확인 및 설정"""
        try:
            account_config = exchange.privateGetAccountConfig()
            
            for config in account_config['data']:
                if config['instType'] == 'SWAP':
                    pos_mode = config['posMode']
                    self.log(f"현재 포지션 모드: {pos_mode}")
                    
                    if pos_mode == 'net_mode':
                        self.position_mode = 'net_mode'
                    else:
                        try:
                            result = exchange.privatePostAccountSetPositionMode({
                                'posMode': 'net_mode'
                            })
                            if result['code'] == '0':
                                self.log("단방향 모드로 변경 성공")
                                self.position_mode = 'net_mode'
                        except Exception as e:
                            self.log(f"포지션 모드 변경 실패: {str(e)}")
                    break
                    
        except Exception as e:
            self.log(f"포지션 모드 확인 실패: {str(e)}")
            self.position_mode = 'net_mode'

    def set_leverages(self):
        """레버리지 설정"""
        for symbol in self.settings['symbols']:
            if symbol.strip():
                try:
                    leverage = self.settings['leverage']
                    self.exchange.set_leverage(leverage, symbol)
                    self.log(f"{symbol} 레버리지 설정 완료: {leverage}x")
                except Exception as e:
                    self.log(f"{symbol} 레버리지 설정 실패: {str(e)}")

    def fetch_balance(self):
        """잔액 조회"""
        try:
            balance = self.exchange.fetch_balance()
            return balance['total']['USDT']
        except Exception as e:
            self.log(f"잔액 조회 오류: {str(e)}")
            return 0

    def fetch_ticker(self, symbol):
        """시세 조회"""
        try:
            ticker = self.exchange.fetch_ticker(symbol)
            return ticker['last']
        except Exception as e:
            self.log(f"{symbol} 시세 조회 오류: {str(e)}")
            raise Exception(f"{symbol} 시세 조회 오류: {str(e)}")

    def fetch_ohlcv(self, symbol, timeframe='1h', limit=80):
        """OHLCV 데이터 조회"""
        try:
            ohlcv = self.exchange.fetch_ohlcv(symbol, timeframe, limit=limit)
            return ohlcv
        except Exception as e:
            self.log(f"{symbol} OHLCV 데이터 조회 오류: {str(e)}")
            return []

    def get_price_precision(self, price):
        """가격에 따른 적절한 소수점 자릿수 반환"""
        if price >= 1000:
            return 2
        elif price >= 100:
            return 3
        elif price >= 10:
            return 4
        elif price >= 1:
            return 5
        elif price >= 0.1:
            return 6
        elif price >= 0.01:
            return 7
        else:
            return 8

    def format_price(self, price):
        """가격을 적절한 소수점으로 포맷팅"""
        precision = self.get_price_precision(price)
        return f"${price:.{precision}f}"

    def calculate_donchian_basis(self, symbol):
        """돈치안 밴드 베이시스 계산 (80시간 고저 평균) - 캐싱 적용"""
        try:
            state = self.symbol_states[symbol]
            current_time = datetime.now()
            
            # 캐시된 데이터가 있고 1시간이 지나지 않았으면 캐시 사용
            if (state['last_donchian_update'] and 
                state['cached_donchian_basis'] and
                current_time - state['last_donchian_update'] < timedelta(hours=1)):
                return state['cached_donchian_basis']
            
            ohlcv_data = self.fetch_ohlcv(symbol, '1h', 80)
            if len(ohlcv_data) < 80:
                return None
            
            # [timestamp, open, high, low, close, volume] 형태
            highs = [candle[2] for candle in ohlcv_data]  # high
            lows = [candle[3] for candle in ohlcv_data]   # low
            
            highest = max(highs)
            lowest = min(lows)
            basis = (highest + lowest) / 2
            
            # 캐시 업데이트
            state['last_donchian_update'] = current_time
            state['cached_donchian_basis'] = basis
            
            # 로그는 간단하게만
            self.log(f"{symbol} 손절 기준가 업데이트: {self.format_price(basis)}")
            return basis
            
        except Exception as e:
            self.log(f"{symbol} 돈치안 베이시스 계산 오류: {str(e)}")
            return None

    def fetch_current_position(self, symbol):
        """포지션 조회"""
        try:
            positions = self.exchange.fetch_positions([symbol])
            for position in positions:
                if position['symbol'] == symbol and float(position['contracts']) > 0:
                    return {
                        'side': position['side'],
                        'amount': float(position['contracts']),
                        'entry_price': float(position['entryPrice']),
                        'leverage': float(position['leverage']),
                        'unrealized_pnl': float(position['unrealizedPnl'])
                    }
            return None
        except Exception as e:
            self.log(f"{symbol} 포지션 조회 오류: {str(e)}")
            return None

    def fetch_open_orders(self, symbol):
        """미체결 주문 조회"""
        try:
            return self.exchange.fetch_open_orders(symbol)
        except Exception as e:
            self.log(f"{symbol} 주문 조회 오류: {str(e)}")
            return []

    def cancel_all_orders(self, symbol):
        """모든 미체결 주문 취소"""
        try:
            open_orders = self.fetch_open_orders(symbol)
            if not open_orders:
                return
                
            for order in open_orders:
                try:
                    self.exchange.cancel_order(order['id'], symbol)
                    self.log(f"{symbol} 주문 취소: ID {order['id']}")
                except Exception as e:
                    self.log(f"{symbol} 주문 취소 실패: ID {order['id']}")
            
            self.log(f"{symbol} 총 {len(open_orders)}개 주문 취소 완료")
        except Exception as e:
            self.log(f"{symbol} 주문 취소 오류: {str(e)}")

    def cancel_tp_order(self, symbol):
        """TP 주문만 취소"""
        try:
            state = self.symbol_states[symbol]
            if state['tp_order_id']:
                try:
                    self.exchange.cancel_order(state['tp_order_id'], symbol)
                    self.log(f"{symbol} TP 주문 취소: ID {state['tp_order_id']}")
                    state['tp_order_id'] = None
                    state['current_tp_price'] = None
                    state['current_tp_type'] = None
                except Exception as e:
                    self.log(f"{symbol} TP 주문 취소 실패: {str(e)}")
                    
        except Exception as e:
            self.log(f"{symbol} TP 주문 취소 오류: {str(e)}")

    def calculate_order_amount(self, level, price, total_balance, symbol):
        """주문 수량 계산"""
        level_str = str(level)
        base_ratio = self.settings['levels'][level_str]['ratio'] / 100.0
        active_symbols_count = len([s for s in self.settings['symbols'] if s.strip()])
        symbol_ratio = base_ratio / active_symbols_count
        capital_multiplier = self.settings.get('capital_usage_ratio', 170) / 170.0
        final_ratio = symbol_ratio * capital_multiplier
        position_value = total_balance * final_ratio
        
        try:
            market = self.exchange.market(symbol)
            contract_size = market.get('contractSize', 1)
            contracts = position_value / (price * contract_size)
            
            if 'precision' in market and 'amount' in market['precision']:
                precision = market['precision']['amount']
                if isinstance(precision, int):
                    contracts = round(contracts, precision)
                else:
                    contracts = float(round(contracts, 8))
            else:
                contracts = float(round(contracts, 8))
            
            min_amount = 0.001
            if 'limits' in market and 'amount' in market['limits']:
                market_min = market['limits']['amount'].get('min', min_amount)
                min_amount = max(min_amount, market_min)
            
            if contracts < min_amount:
                contracts = min_amount
            
            return contracts
                
        except Exception as e:
            self.log(f"{symbol} 주문 수량 계산 오류: {str(e)}")
            contracts = position_value / price
            return max(float(round(contracts, 8)), 0.001)

    def place_market_order(self, symbol, side, amount):
        """시장가 주문"""
        try:
            params = {}
            if hasattr(self, 'position_mode') and self.position_mode == 'long_short_mode':
                if side == 'buy':
                    params['posSide'] = 'long'
                elif side == 'sell':
                    params['posSide'] = 'short'
            
            order = self.exchange.create_market_order(symbol, side, amount, params=params)
            self.log(f"{symbol} {side} 시장가 주문 성공: 계약수 {amount}")
            return order
            
        except Exception as e:
            self.log(f"{symbol} 시장가 주문 오류: {str(e)}")
            return None

    def place_limit_order(self, symbol, side, price, amount, level):
        """지정가 주문"""
        try:
            params = {}
            if hasattr(self, 'position_mode') and self.position_mode == 'long_short_mode':
                if side == 'buy':
                    params['posSide'] = 'long'
                elif side == 'sell':
                    params['posSide'] = 'short'
            
            order = self.exchange.create_limit_order(symbol, side, amount, price, params=params)
            self.log(f"{symbol} {level}회차 {side} 지정가 주문 실행: 가격 {price}, 수량 {amount}")
            return order
        except Exception as e:
            self.log(f"{symbol} 지정가 주문 오류: {str(e)}")
            return None

    def place_tp_order(self, symbol, tp_price, amount, tp_type):
        """TP 주문 생성 - 에러 처리 강화"""
        try:
            params = {"reduceOnly": True}
            if hasattr(self, 'position_mode') and self.position_mode == 'long_short_mode':
                params['posSide'] = 'long'
            
            order = self.exchange.create_limit_order(symbol, "sell", amount, tp_price, params=params)
            
            if order and order.get('id'):
                state = self.symbol_states[symbol]
                state['tp_order_id'] = order['id']
                state['current_tp_price'] = tp_price
                state['current_tp_type'] = tp_type
                
                tp_type_korean = "익절" if tp_type == "profit" else "손절"
                self.log(f"{symbol} {tp_type_korean} TP 주문 생성: 가격 {self.format_price(tp_price)}, 수량 {amount}, ID {order['id']}")
                return order
            else:
                self.log(f"{symbol} TP 주문 생성 실패 - 주문 정보 없음")
                return None
                
        except Exception as e:
            self.log(f"{symbol} TP 주문 생성 오류: {str(e)}")
            return None

    def check_tp_execution(self, symbol, position):
        """TP 주문 체결 확인 - 개선된 버전"""
        try:
            state = self.symbol_states[symbol]
            
            # TP 주문이 있는 경우에만 확인
            if not state.get('tp_order_id'):
                return False
            
            try:
                # TP 주문 상태 확인
                tp_order = self.exchange.fetch_order(state['tp_order_id'], symbol)
                
                # 주문이 체결된 경우
                if tp_order['status'] in ['closed', 'filled']:
                    tp_type_korean = "익절" if state.get('current_tp_type') == "profit" else "손절"
                    self.log(f"{symbol} {tp_type_korean} TP 주문 체결 감지 - 포지션 정리 시작")
                    
                    # 상태 초기화
                    self.reset_symbol_state_after_close(symbol)
                    return True
                    
            except Exception as order_error:
                # 주문 조회 실패 시 - 주문이 이미 체결되어 삭제되었을 가능성
                self.log(f"{symbol} TP 주문 조회 실패: {str(order_error)}")
                
                # 포지션이 없다면 TP가 체결되었을 가능성이 높음
                if not position:
                    self.log(f"{symbol} 포지션 없음 + TP 주문 조회 실패 = TP 체결로 판단")
                    self.reset_symbol_state_after_close(symbol)
                    return True
            
            return False
            
        except Exception as e:
            self.log(f"{symbol} TP 체결 확인 오류: {str(e)}")
            return False

    def reset_symbol_state_after_close(self, symbol):
        """포지션 청산 후 상태 초기화 - 주문 취소 추가"""
        try:
            state = self.symbol_states[symbol]
            
            # 핵심 수정: 모든 미체결 주문 취소
            self.log(f"{symbol} 청산 완료 - 모든 미체결 주문 취소 시작")
            self.cancel_all_orders(symbol)
            time.sleep(1)  # 주문 취소 완료 대기
            
            # 청산 시간 기록
            state['last_close_time'] = datetime.now()
            
            # 상태 초기화
            state['is_first_entry'] = False
            state['order_level'] = 0
            state['just_entered'] = False
            state['tp_order_id'] = None
            state['current_tp_price'] = None
            state['current_tp_type'] = None
            state['reached_target_level'] = False
            
            # 캐시 및 테이블 초기화
            state['last_donchian_update'] = None
            state['cached_donchian_basis'] = None
            state['cumulative_amounts'] = {}
            
            self.log(f"{symbol} 상태 초기화 완료 - 60초 후 재진입 가능")
            
        except Exception as e:
            self.log(f"{symbol} 상태 초기화 오류: {str(e)}")

    def check_position_status_change(self, symbol, prev_position, current_position):
        """포지션 상태 변화 감지 및 처리 - 주문 취소 강화"""
        try:
            state = self.symbol_states[symbol]
            
            # 포지션이 있었는데 없어진 경우 (청산됨)
            if prev_position and not current_position:
                # TP 주문이 있었다면 체결된 것으로 판단
                if state.get('tp_order_id'):
                    tp_type_korean = "익절" if state.get('current_tp_type') == "profit" else "손절"
                    self.log(f"{symbol} 포지션 청산 감지 - {tp_type_korean} 완료")
                else:
                    self.log(f"{symbol} 포지션 청산 감지 - 수동 청산으로 추정")
                
                # 핵심: 즉시 모든 주문 취소 후 상태 초기화
                self.log(f"{symbol} 청산 감지 즉시 - 모든 주문 취소 실행")
                self.cancel_all_orders(symbol)
                time.sleep(0.5)
                
                # 상태 초기화
                self.reset_symbol_state_after_close(symbol)
                return True
                
            return False
            
        except Exception as e:
            self.log(f"{symbol} 포지션 상태 변화 확인 오류: {str(e)}")
            return False

    def update_tp_order(self, symbol, position):
        """TP 주문 업데이트 - 안정성 개선"""
        try:
            if not position or position['side'] != 'long':
                return
            
            state = self.symbol_states[symbol]
            
            # 익절가 계산
            take_profit_percent = self.settings['take_profit_percent'] / 100.0
            profit_price = position['entry_price'] * (1 + take_profit_percent)
            
            # 손절 기준가 계산 (목표 차수 도달 시만, 1시간마다만 업데이트)
            donchian_price = None
            if state['reached_target_level']:
                donchian_price = self.calculate_donchian_basis(symbol)
            
            # 더 가까운(낮은) 가격을 TP로 설정
            if donchian_price and donchian_price < profit_price:
                target_tp_price = donchian_price
                target_tp_type = "stop_loss"
            else:
                target_tp_price = profit_price
                target_tp_type = "profit"
            
            # 현재 TP와 비교하여 업데이트 필요성 확인
            current_tp = state.get('current_tp_price')
            current_type = state.get('current_tp_type')
            
            # TP 가격이나 타입이 변경된 경우에만 업데이트
            price_changed = not current_tp or abs(current_tp - target_tp_price) > 0.01
            type_changed = current_type != target_tp_type
            
            if price_changed or type_changed:
                # 기존 TP 주문 취소
                if state['tp_order_id']:
                    self.cancel_tp_order(symbol)
                    time.sleep(0.5)
                
                # 새 TP 주문 생성
                tp_order = self.place_tp_order(symbol, target_tp_price, position['amount'], target_tp_type)
                
                if tp_order:
                    tp_type_korean = "익절" if target_tp_type == "profit" else "손절"
                    self.log(f"{symbol} TP 업데이트 완료: {tp_type_korean} {self.format_price(target_tp_price)}")
                else:
                    self.log(f"{symbol} TP 주문 생성 실패")
            
        except Exception as e:
            self.log(f"{symbol} TP 업데이트 오류: {str(e)}")

    def close_position_market(self, symbol):
        """포지션 청산 (긴급시 사용)"""
        position = self.fetch_current_position(symbol)
        if position and position['side'] == 'long':
            try:
                params = {"reduceOnly": True}
                if hasattr(self, 'position_mode') and self.position_mode == 'long_short_mode':
                    params['posSide'] = 'long'
                
                close_order = self.exchange.create_market_order(symbol, "sell", position["amount"], params=params)
                self.log(f"{symbol} 롱 포지션 시장가 청산: {position['amount']}")
                
                self.symbol_states[symbol]['last_close_time'] = datetime.now()
                self.symbol_states[symbol]['is_first_entry'] = False
                self.symbol_states[symbol]['reached_target_level'] = False
                # 돈치안 캐시와 누적 수량 테이블도 초기화
                self.symbol_states[symbol]['last_donchian_update'] = None
                self.symbol_states[symbol]['cached_donchian_basis'] = None
                self.symbol_states[symbol]['cumulative_amounts'] = {}
                return close_order
            except Exception as e:
                self.log(f"{symbol} 포지션 청산 오류: {str(e)}")
                return None
        return None

    def close_all_positions(self):
        """모든 포지션 청산 (긴급 정지용)"""
        self.log("모든 포지션 청산 시작")
        for symbol in self.settings['symbols']:
            if symbol.strip():
                try:
                    position = self.fetch_current_position(symbol)
                    if position:
                        self.close_position_market(symbol)
                        time.sleep(1)  # 주문 간격
                except Exception as e:
                    self.log(f"{symbol} 포지션 청산 오류: {str(e)}")

    def place_initial_long_order(self, symbol, current_price, total_balance):
        """초기 롱 주문 생성"""
        level = 1
        long_amount = self.calculate_order_amount(level, current_price, total_balance, symbol)
        long_order = self.place_market_order(symbol, "buy", long_amount)
        
        if long_order:
            self.log(f"{symbol} 1회차 롱 시장가 주문 생성 완료 - 수량: {long_amount}")
            return True
        return False

    def place_all_next_level_orders(self, symbol, entry_price, total_balance):
        """후속 회차 주문 생성"""
        self.log(f"{symbol} 롱 포지션 진입 후 모든 후속 회차 주문 생성 시작")
        
        max_level = 10 if '10' in self.settings['levels'] else 9
        for level in range(2, max_level + 1):
            level_str = str(level)
            if level_str in self.settings['levels']:
                distance = self.settings['levels'][level_str]['distance'] / 100.0
                next_price = entry_price * (1 - distance)
                amount = self.calculate_order_amount(level, next_price, total_balance, symbol)
                order = self.place_limit_order(symbol, "buy", next_price, amount, level)
                
                if order:
                    self.log(f"{symbol} {level}회차 롱 주문 생성 완료 - 가격: {next_price}")
        
        self.symbol_states[symbol]['order_level'] = max_level
        self.log(f"{symbol} 모든 후속 회차 주문 생성 완료")

    def calculate_cumulative_amounts(self, symbol, entry_price, total_balance):
        """각 차수별 누적 수량 테이블 생성"""
        try:
            state = self.symbol_states[symbol]
            cumulative_amounts = {}
            cumulative_total = 0
            
            # 1~10차까지 누적 수량 계산
            for level in range(1, 11):
                level_str = str(level)
                if level_str in self.settings['levels']:
                    amount = self.calculate_order_amount(level, entry_price, total_balance, symbol)
                    cumulative_total += amount
                    cumulative_amounts[level] = cumulative_total
            
            state['cumulative_amounts'] = cumulative_amounts
            self.log(f"{symbol} 누적 수량 테이블 생성 완료")
            
        except Exception as e:
            self.log(f"{symbol} 누적 수량 테이블 생성 오류: {str(e)}")

    def get_current_level_from_position(self, symbol, position_amount):
        """포지션 수량을 기준으로 현재 진입 차수 계산"""
        try:
            state = self.symbol_states[symbol]
            cumulative_amounts = state.get('cumulative_amounts', {})
            
            if not cumulative_amounts:
                return 1  # 누적 테이블이 없으면 1차로 가정
            
            # 현재 포지션 수량과 가장 가까운 누적 수량 찾기
            closest_level = 1
            min_diff = float('inf')
            
            for level, cumulative_amount in cumulative_amounts.items():
                diff = abs(position_amount - cumulative_amount)
                if diff < min_diff:
                    min_diff = diff
                    closest_level = level
            
            return closest_level
            
        except Exception as e:
            self.log(f"{symbol} 현재 차수 계산 오류: {str(e)}")
            return 1

    def check_level_progress(self, symbol, position, open_orders):
        """진입 차수 진행 상황 확인 - 누적 수량 기준"""
        try:
            state = self.symbol_states[symbol]
            target_level = self.settings.get('donchian_activation_level', 6)
            
            if not position:
                return
            
            # 누적 수량 테이블이 없으면 생성
            if not state.get('cumulative_amounts'):
                total_balance = self.fetch_balance()
                self.calculate_cumulative_amounts(symbol, position['entry_price'], total_balance)
            
            # 현재 포지션 수량을 기준으로 진입 차수 계산
            current_level = self.get_current_level_from_position(symbol, position['amount'])
            
            # 목표 차수 이상에 도달했는지 확인
            if current_level >= target_level and not state['reached_target_level']:
                state['reached_target_level'] = True
                self.log(f"{symbol} {current_level}차 진입 감지 - 손절허용 레벨 활성화")
                
        except Exception as e:
            self.log(f"{symbol} 레벨 진행 확인 오류: {str(e)}")

    def can_enter_position(self, symbol):
        """포지션 진입 가능 여부 확인"""
        state = self.symbol_states[symbol]
        
        if state['is_first_entry']:
            return True
        
        if state['last_close_time']:
            elapsed = datetime.now() - state['last_close_time']
            wait_time = timedelta(seconds=60)  # 고정 60초
            return elapsed >= wait_time
        
        return True

    def process_symbol(self, symbol, total_balance):
        """개별 종목 처리 - 주문 취소 로직 강화"""
        try:
            if not self.symbol_states[symbol]['is_active']:
                return
            
            current_price = self.fetch_ticker(symbol)
            position = self.fetch_current_position(symbol)
            open_orders = self.fetch_open_orders(symbol)
            
            state = self.symbol_states[symbol]
            prev_position = state['current_position']
            
            # 추가: 포지션이 없는데 주문이 있는 경우 모두 취소
            if not position and open_orders:
                self.log(f"{symbol} 포지션 없음 + 미체결 주문 {len(open_orders)}개 감지 - 모든 주문 취소")
                self.cancel_all_orders(symbol)
                time.sleep(1)
                open_orders = []  # 주문 목록 초기화
            
            # 포지션 상태 변화 먼저 확인
            if self.check_position_status_change(symbol, prev_position, position):
                # 포지션이 청산된 경우 더 이상 처리하지 않음
                state['current_position'] = position
                state['current_orders'] = []  # 주문 목록 초기화
                return
            
            # 포지션이 있는 경우 TP 체결 확인
            if position and position['side'] == 'long':
                if self.check_tp_execution(symbol, position):
                    # TP가 체결된 경우 더 이상 처리하지 않음
                    state['current_position'] = None
                    state['current_orders'] = []
                    return
            
            # 포지션 변경 감지 (새로 진입한 경우)
            if not prev_position and position and position['side'] == 'long' and not state.get('just_entered', False):
                self.log(f"{symbol} 새 롱 포지션 감지: {position['amount']} @ {position['entry_price']}")
                
                if open_orders:
                    self.cancel_all_orders(symbol)
                    time.sleep(1)
                
                self.place_all_next_level_orders(symbol, position['entry_price'], total_balance)
                state['just_entered'] = True
                
                # 누적 수량 테이블 생성
                self.calculate_cumulative_amounts(symbol, position['entry_price'], total_balance)
                
                # 초기 TP 설정
                self.update_tp_order(symbol, position)
            
            # 포지션이 없는 경우
            elif not position:
                state['just_entered'] = False
                
                # 중요: 주문이 없고 진입 가능한 경우에만 진입
                if not open_orders and self.can_enter_position(symbol):
                    self.log(f"{symbol} 포지션 없음, 초기 롱 시장가 진입")
                    if self.place_initial_long_order(symbol, current_price, total_balance):
                        state['order_level'] = 1
                        state['just_entered'] = True
                        time.sleep(3)
                        new_position = self.fetch_current_position(symbol)
                        if new_position and new_position['side'] == 'long':
                            self.log(f"{symbol} 시장가 진입 확인됨, 후속 주문 생성")
                            self.place_all_next_level_orders(symbol, new_position['entry_price'], total_balance)
                            # 누적 수량 테이블 생성
                            self.calculate_cumulative_amounts(symbol, new_position['entry_price'], total_balance)
                            # TP 설정
                            self.update_tp_order(symbol, new_position)
                elif open_orders:
                    # 진입 대기 중이면서 주문이 있는 경우
                    if self.can_enter_position(symbol):
                        self.log(f"{symbol} 진입 대기시간 완료 - 기존 주문 유지")
                    else:
                        remaining_time = 60 - (datetime.now() - state['last_close_time']).total_seconds()
                        self.log(f"{symbol} 재진입 대기 중 - {remaining_time:.0f}초 남음")
            
            # 포지션이 있는 경우 추가 처리
            elif position and position['side'] == 'long':
                # 레벨 진행 상황 확인
                self.check_level_progress(symbol, position, open_orders)
                
                # TP 주문 업데이트 (조건 변경 시)
                self.update_tp_order(symbol, position)
            
            # 상태 업데이트
            state['current_position'] = position
            state['current_orders'] = open_orders
            
        except Exception as e:
            self.log(f"{symbol} 처리 오류: {str(e)}")

    def show_status(self):
        """현재 상태 출력"""
        status_msg = "\n===== 현재 상태 ====="
        self.log(status_msg)
        
        for symbol in self.settings['symbols']:
            if not symbol.strip():
                continue
                
            try:
                current_price = self.fetch_ticker(symbol)
                position = self.fetch_current_position(symbol)
                open_orders = self.fetch_open_orders(symbol)
                state = self.symbol_states[symbol]
                
                self.log(f"\n--- {symbol} ---")
                self.log(f"현재가: {self.format_price(current_price)}")
                self.log(f"활성화: {'예' if state['is_active'] else '아니오'}")
                
                if position:
                    self.log(f"포지션: {position['side']} {position['amount']:.6f}")
                    self.log(f"진입가: {self.format_price(position['entry_price'])}")
                    self.log(f"미실현 손익: ${position['unrealized_pnl']:.2f}")
                    
                    # TP 정보 표시
                    if state['current_tp_price']:
                        tp_type_korean = "익절" if state['current_tp_type'] == "profit" else "손절"
                        self.log(f"활성 TP: {tp_type_korean} {self.format_price(state['current_tp_price'])}")
                    
                    # 손절허용 레벨 활성화 상태
                    target_level = self.settings.get('donchian_activation_level', 6)
                    if state['reached_target_level']:
                        self.log(f"손절허용 레벨: 활성화됨 ({target_level}차 이상 진입)")
                    else:
                        self.log(f"손절허용 레벨: 비활성화 ({target_level}차 미도달)")
                        
                else:
                    self.log("포지션: 없음")
                
                self.log(f"미체결 주문: {len(open_orders)}개")
                if state['last_close_time']:
                    elapsed = datetime.now() - state['last_close_time']
                    wait_time = timedelta(seconds=60)
                    remaining = max(0, (wait_time - elapsed).total_seconds())
                    self.log(f"진입 대기시간: {remaining:.0f}초 남음")
                
            except Exception as e:
                self.log(f"{symbol} 상태 조회 오류: {str(e)}")
        
        # 계좌 정보
        try:
            total_balance = self.fetch_balance()
            self.log(f"\n총 잔액: ${total_balance:.2f} USDT")
        except Exception as e:
            self.log(f"잔액 조회 오류: {str(e)}")
        
        self.log("=" * 50)

    def run(self):
        """메인 실행 루프"""
        self.log("자동매매 시작")
        
        while not self.should_stop:
            try:
                total_balance = self.fetch_balance()
                
                for symbol in self.settings['symbols']:
                    if self.should_stop:
                        break
                    if symbol.strip():
                        self.process_symbol(symbol, total_balance)
                        time.sleep(1)
                
                # 상태 출력 (10분마다)
                if hasattr(self, 'last_status_time'):
                    if datetime.now() - self.last_status_time > timedelta(minutes=10):
                        self.show_status()
                        self.last_status_time = datetime.now()
                else:
                    self.show_status()
                    self.last_status_time = datetime.now()
                
                time.sleep(30)  # 고정 30초 간격
                
            except Exception as e:
                self.log(f"메인 루프 오류: {str(e)}")
                time.sleep(10)
        
        self.log("자동매매 종료")

    def stop(self):
        """자동매매 중지"""
        self.should_stop = True
        self.log("자동매매 중지 요청됨")

    def emergency_stop(self):
        """긴급 정지 - 모든 주문 취소 및 포지션 청산"""
        self.log("긴급 정지 시작 - 모든 주문 취소 및 포지션 청산")
        
        # 모든 주문 취소
        for symbol in self.settings['symbols']:
            if symbol.strip():
                try:
                    self.cancel_all_orders(symbol)
                    time.sleep(0.5)
                except Exception as e:
                    self.log(f"{symbol} 긴급 주문 취소 오류: {str(e)}")
        
        # 모든 포지션 청산
        self.close_all_positions()
        self.stop()

class TradingGUI:
    """기본형 GUI 인터페이스"""
    
    def __init__(self):
        # self.auth = GoogleSheetsAuth()
        self.trader = None
        self.trading_thread = None
        self.log_queue = queue.Queue()
        
        self.root = tk.Tk()
        self.root.title("OKX TriCore Bot")
        self.root.geometry("1000x700")
        
        self.setup_gui()
        self.load_settings()
        
        # 로그 업데이트 타이머
        self.root.after(100, self.update_logs)

    def setup_gui(self):
        """GUI 레이아웃 설정"""
        # 메인 프레임
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # 제목
        title_label = ttk.Label(main_frame, text="OKX TriCore Bot", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # 사용자 정보 프레임
        self.user_frame = ttk.LabelFrame(main_frame, text="사용자 정보")
        self.user_frame.pack(fill='x', pady=(0, 10))
        
        self.user_label = ttk.Label(self.user_frame, text="로그인이 필요합니다")
        self.user_label.pack(pady=10, padx=10)
        
        # 설정 프레임
        settings_frame = ttk.LabelFrame(main_frame, text="거래 설정")
        settings_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        # 설정 노트북
        self.notebook = ttk.Notebook(settings_frame)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.setup_api_tab()
        self.setup_trading_tab()
        
        # 컨트롤 프레임
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill='x', pady=(0, 10))
        
        # 버튼들
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(side='left')
        
        self.login_btn = ttk.Button(button_frame, text="로그인", 
                                   command=self.login)
        self.login_btn.pack(side='left', padx=(0, 5))
        
        self.start_btn = ttk.Button(button_frame, text="매매 시작", 
                                   command=self.start_trading,
                                   state='abled')
        self.start_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="매매 중지", 
                                  command=self.stop_trading,
                                  state='abled')
        self.stop_btn.pack(side='left', padx=5)
        
        self.emergency_btn = ttk.Button(button_frame, text="긴급 정지", 
                                       command=self.emergency_stop,
                                       state='abled')
        self.emergency_btn.pack(side='left', padx=5)
        
        # 상태 라벨
        self.status_label = ttk.Label(control_frame, text="상태: 대기 중")
        self.status_label.pack(side='right')
        
        # 로그 프레임
        log_frame = ttk.LabelFrame(main_frame, text="실시간 로그")
        log_frame.pack(fill='both', expand=True)
        
        # 로그 텍스트
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, 
                                                 font=('Consolas', 9))
        self.log_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # 메뉴
        self.setup_menu()

    def setup_api_tab(self):
        """API 설정 탭"""
        api_frame = ttk.Frame(self.notebook)
        self.notebook.add(api_frame, text="API 설정")
        
        # API Key
        ttk.Label(api_frame, text="API Key:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.api_key_entry = ttk.Entry(api_frame, width=50, show='*')
        self.api_key_entry.grid(row=0, column=1, padx=5, pady=5)
        # 기본값 설정
        # self.api_key_entry.insert(0, 'jlkhohihl')
        
        # Secret Key
        ttk.Label(api_frame, text="Secret Key:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.secret_key_entry = ttk.Entry(api_frame, width=50, show='*')
        self.secret_key_entry.grid(row=1, column=1, padx=5, pady=5)
        # 기본값 설정
        # self.secret_key_entry.insert(0, 'jlkhohihl')        
        
        # Password
        ttk.Label(api_frame, text="Password:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.password_entry = ttk.Entry(api_frame, width=50, show='*')
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        # 기본값 설정
        # self.password_entry.insert(0, 'jlkhohihl')        

    def setup_trading_tab(self):
        """거래 설정 탭"""
        trading_frame = ttk.Frame(self.notebook)
        self.notebook.add(trading_frame, text="거래 설정")
        
        # 거래 종목 (3개 필드)
        ttk.Label(trading_frame, text="거래 종목:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        
        symbol_frame = ttk.Frame(trading_frame)
        symbol_frame.grid(row=0, column=1, sticky='w', padx=5, pady=5)
        
        self.symbol1_entry = ttk.Entry(symbol_frame, width=20)
        self.symbol1_entry.pack(side='left', padx=(0, 5))
        self.symbol1_entry.insert(0, "XRP/USDT:USDT")
        
        self.symbol2_entry = ttk.Entry(symbol_frame, width=20)
        self.symbol2_entry.pack(side='left', padx=5)
        self.symbol2_entry.insert(0, "DOGE/USDT:USDT")
        
        self.symbol3_entry = ttk.Entry(symbol_frame, width=20)
        self.symbol3_entry.pack(side='left', padx=5)
        self.symbol3_entry.insert(0, "ADA/USDT:USDT")
        
        # 레버리지
        ttk.Label(trading_frame, text="레버리지:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.leverage_entry = ttk.Entry(trading_frame, width=20)
        self.leverage_entry.grid(row=1, column=1, sticky='w', padx=5, pady=5)
        self.leverage_entry.insert(0, "3")
        
        # 익절 퍼센트
        ttk.Label(trading_frame, text="익절 퍼센트 (%):").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.take_profit_entry = ttk.Entry(trading_frame, width=20)
        self.take_profit_entry.grid(row=2, column=1, sticky='w', padx=5, pady=5)
        self.take_profit_entry.insert(0, "1.0")
        
        # 자본 사용 비율
        ttk.Label(trading_frame, text="자본 사용 비율 (%):").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.capital_usage_entry = ttk.Entry(trading_frame, width=20)
        self.capital_usage_entry.grid(row=3, column=1, sticky='w', padx=5, pady=5)
        self.capital_usage_entry.insert(0, "170")
        
        # 손절허용 레벨
        ttk.Label(trading_frame, text="손절허용 레벨:").grid(row=4, column=0, sticky='w', padx=5, pady=5)
        self.donchian_level_entry = ttk.Entry(trading_frame, width=20)
        self.donchian_level_entry.grid(row=4, column=1, sticky='w', padx=5, pady=5)
        self.donchian_level_entry.insert(0, "6")
        
        # 헷지 체크박스
        ttk.Label(trading_frame, text="헷지:").grid(row=5, column=0, sticky='w', padx=5, pady=5)
        self.hedge_var = tk.BooleanVar()
        self.hedge_checkbox = ttk.Checkbutton(trading_frame, variable=self.hedge_var)
        self.hedge_checkbox.grid(row=5, column=1, sticky='w', padx=5, pady=5)

    def setup_menu(self):
        """메뉴 설정"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # 파일 메뉴
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="파일", menu=file_menu)
        file_menu.add_command(label="설정 저장", command=self.save_settings)
        file_menu.add_command(label="설정 불러오기", command=self.load_settings_file)
        file_menu.add_separator()
        file_menu.add_command(label="종료", command=self.root.quit)
        
        # 계정 메뉴
        account_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="계정", menu=account_menu)
        account_menu.add_command(label="로그아웃", command=self.logout)
        
        # 사용법 메뉴
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="사용법", menu=help_menu)
        help_menu.add_command(label="최초 세팅 방법", command=self.show_initial_setup)
        help_menu.add_command(label="사용 설명서", command=self.show_user_manual)

    def show_initial_setup(self):
        """최초 세팅 방법 표시"""
        setup_text = """
=== 최초 세팅 방법 ===

1. OKX API 설정
   - OKX 거래소에서 API 키 생성
   - API Key, Secret Key, Passphrase 복사
   - 프로그램의 API 설정 탭에 입력

2. 거래 설정
   - 거래할 암호화폐 종목 입력 (최대 3개)
   - 레버리지 설정 (권장: 3x 이하)
   - 익절 퍼센트 설정 (권장: 1-5%)
   - 자본 사용 비율 설정 (기본: 170%)
   - 손절허용 레벨 설정 (기본: 6차)

3. 로그인 및 승인
   - '로그인' 버튼 클릭
   - Google 계정으로 로그인
   - 관리자 승인 후 사용 가능

주의사항:
- 실제 거래 전 충분한 테스트 필요
- 손실 가능성을 항상 고려
- 자본 관리 철저히 수행
        """
        
        self.show_text_window("최초 세팅 방법", setup_text)

    def show_user_manual(self):
        """사용 설명서 표시"""
        manual_text = """
=== 사용 설명서 ===

1. 프로그램 개요
   - OKX TriCore Bot
   - 멀티 심볼 동시 거래 지원
   - 자동화된 거래 관리 시스템

2. 주요 기능
   - 매매 시작/중지: 일반적인 시작/정지
   - 긴급 정지: 모든 주문 취소 + 포지션 청산
   - 실시간 로그: 거래 현황 실시간 모니터링
   - 설정 저장/불러오기: 설정 백업 기능

3. 자본 사용 비율
   - 기본값: 170% (전체 잔고 대비)
   - 각 회차별 진입 비율:
     1차: 5%, 2차: 5%, 3차: 7.5%, 4차: 10%
     5차: 12.5%, 6차: 15%, 7차: 20%, 8차: 25%
     9차: 30%, 10차: 40%
   - 비율 조정 시 모든 회차가 비례적으로 변경

4. 설정 항목
   - 거래 종목: 최대 3개 동시 거래
   - 레버리지: 권장 3x 이하
   - 익절 퍼센트: 권장 1-5%
   - 자본 사용 비율: 전체 잔고 대비 사용 비율
   - 손절허용 레벨: 위험 관리 설정

5. 위험 관리
   - 레버리지는 신중하게 설정
   - 충분한 잔고 유지 필요
   - 시장 상황에 따른 수동 개입 고려
   - 정기적인 수익 실현 권장

6. 문제 해결
   - 연결 오류: API 키 확인
   - 인증 오류: 로그인 상태 확인
   - 주문 실패: 잔고 및 거래소 상태 확인
   - 긴급 상황: 긴급 정지 버튼 사용

주의: 이 프로그램은 투자 손실 위험을 포함합니다.
충분한 이해와 테스트 후 사용하시기 바랍니다.
        """
        
        self.show_text_window("사용 설명서", manual_text)

    def show_text_window(self, title, text):
        """텍스트 표시 창"""
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("800x600")
        
        text_widget = scrolledtext.ScrolledText(window, wrap=tk.WORD, 
                                               font=('Arial', 10))
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        text_widget.insert('1.0', text)
        text_widget.config(state='disabled')

    def login(self):
        """로그인"""
        try:
            self.status_label.config(text="상태: 인증 중...")
            self.root.update()
            
            if self.auth.check_authorization():
                user_info = self.auth.get_user_info()
                self.user_label.config(text=f"로그인됨: {user_info['email']}")
                self.login_btn.config(state='disabled')
                self.start_btn.config(state='normal')
                self.status_label.config(text="상태: 로그인 완료")
                self.log_message("로그인 성공")
            else:
                self.status_label.config(text="상태: 로그인 실패")
                self.log_message("로그인 실패")
        except Exception as e:
            messagebox.showerror("로그인 오류", f"로그인 중 오류가 발생했습니다:\n{str(e)}")
            self.status_label.config(text="상태: 로그인 오류")

    def logout(self):
        """로그아웃"""
        if self.trader:
            self.stop_trading()
        
        self.auth.logout()
        self.user_label.config(text="로그인이 필요합니다")
        self.login_btn.config(state='normal')
        self.start_btn.config(state='disabled')
        self.status_label.config(text="상태: 로그아웃됨")
        self.log_message("로그아웃 완료")

    def get_settings_from_gui(self):
        """GUI에서 설정 읽기"""
        try:
            # 거래 종목 수집
            symbols = []
            for entry in [self.symbol1_entry, self.symbol2_entry, self.symbol3_entry]:
                symbol = entry.get().strip()
                if symbol:
                    symbols.append(symbol)
            
            settings = {
                'api_key': self.api_key_entry.get(),
                'secret_key': self.secret_key_entry.get(),
                'password': self.password_entry.get(),
                'symbols': symbols,
                'leverage': int(self.leverage_entry.get()),
                'take_profit_percent': float(self.take_profit_entry.get()),
                'capital_usage_ratio': float(self.capital_usage_entry.get()),
                'donchian_activation_level': int(self.donchian_level_entry.get()),
                'hedge_enabled': self.hedge_var.get(),
                'min_amount': 0.001
            }
            
            return settings
        except ValueError as e:
            raise Exception(f"설정값 오류: {str(e)}")

    def start_trading(self):
        """매매 시작"""
        try:
            settings = self.get_settings_from_gui()
            
            # 필수 설정 확인
            if not all([settings['api_key'], settings['secret_key'], settings['password']]):
                messagebox.showerror("설정 오류", "API 키 정보를 모두 입력해주세요.")
                return
            
            if not settings['symbols']:
                messagebox.showerror("설정 오류", "거래할 종목을 최소 1개 이상 입력해주세요.")
                return
            
            # 손절허용 레벨 유효성 확인
            if settings['donchian_activation_level'] < 1 or settings['donchian_activation_level'] > 10:
                messagebox.showerror("설정 오류", "손절허용 레벨은 1~10 사이의 값이어야 합니다.")
                return
            
            # 트레이더 생성
            self.trader = MultiSymbolAutoTrader(settings, self.log_queue)
            
            # 별도 스레드에서 실행 - daemon=False로 변경하여 안정성 확보
            self.trading_thread = threading.Thread(target=self.trader.run, daemon=False)
            self.trading_thread.start()
            
            # UI 업데이트
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
            self.emergency_btn.config(state='normal')
            self.status_label.config(text="상태: 매매 중")
            
            self.log_message("자동매매가 시작되었습니다.")
            
        except Exception as e:
            messagebox.showerror("시작 오류", f"매매 시작 중 오류가 발생했습니다:\n{str(e)}")

    def stop_trading(self):
        """매매 중지"""
        if self.trader:
            self.trader.stop()
            
            # 스레드가 완전히 종료될 때까지 대기
            if self.trading_thread and self.trading_thread.is_alive():
                self.trading_thread.join(timeout=5)  # 최대 5초 대기
            
            # UI 업데이트
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
            self.emergency_btn.config(state='disabled')
            self.status_label.config(text="상태: 중지됨")
            
            self.log_message("자동매매가 중지되었습니다.")

    def emergency_stop(self):
        """긴급 정지"""
        if self.trader:
            if messagebox.askyesno("긴급 정지", "모든 미체결 주문을 취소하고 포지션을 청산하며 매매를 중지하시겠습니까?"):
                self.trader.emergency_stop()
                
                # 스레드가 완전히 종료될 때까지 대기
                if self.trading_thread and self.trading_thread.is_alive():
                    self.trading_thread.join(timeout=10)  # 긴급정지는 10초 대기
                
                # UI 업데이트
                self.start_btn.config(state='normal')
                self.stop_btn.config(state='disabled')
                self.emergency_btn.config(state='disabled')
                self.status_label.config(text="상태: 긴급 정지됨")
                
                self.log_message("긴급 정지가 실행되었습니다.")

    def update_logs(self):
        """로그 업데이트"""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} {message}\n")
                self.log_text.see(tk.END)
        except queue.Empty:
            pass
        
        self.root.after(100, self.update_logs)

    def log_message(self, message):
        """GUI 로그에 메시지 추가"""
        self.log_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} {message}\n")
        self.log_text.see(tk.END)

    def save_settings(self):
        """설정 저장"""
        try:
            settings = self.get_settings_from_gui()
            
            # API 키 정보는 저장하지 않음
            safe_settings = settings.copy()
            safe_settings.pop('api_key', None)
            safe_settings.pop('secret_key', None)
            safe_settings.pop('password', None)
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(safe_settings, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("저장 완료", "설정이 저장되었습니다.")
                
        except Exception as e:
            messagebox.showerror("저장 오류", f"설정 저장 중 오류가 발생했습니다:\n{str(e)}")

    def load_settings_file(self):
        """설정 파일 불러오기"""
        try:
            filename = filedialog.askopenfilename(
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                
                self.load_settings_to_gui(settings)
                messagebox.showinfo("불러오기 완료", "설정이 불러와졌습니다.")
                
        except Exception as e:
            messagebox.showerror("불러오기 오류", f"설정 불러오기 중 오류가 발생했습니다:\n{str(e)}")

    def load_settings(self):
        """기본 설정 불러오기"""
        try:
            if os.path.exists('settings.json'):
                with open('settings.json', 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                self.load_settings_to_gui(settings)
        except Exception as e:
            logger.warning(f"설정 불러오기 실패: {str(e)}")

    def load_settings_to_gui(self, settings):
        """설정을 GUI에 적용"""
        try:
            # 거래 종목 설정
            if 'symbols' in settings:
                symbols = settings['symbols']
                entries = [self.symbol1_entry, self.symbol2_entry, self.symbol3_entry]
                
                for i, entry in enumerate(entries):
                    entry.delete(0, tk.END)
                    if i < len(symbols):
                        entry.insert(0, symbols[i])
            
            if 'leverage' in settings:
                self.leverage_entry.delete(0, tk.END)
                self.leverage_entry.insert(0, str(settings['leverage']))
            
            if 'take_profit_percent' in settings:
                self.take_profit_entry.delete(0, tk.END)
                self.take_profit_entry.insert(0, str(settings['take_profit_percent']))
            
            if 'capital_usage_ratio' in settings:
                self.capital_usage_entry.delete(0, tk.END)
                self.capital_usage_entry.insert(0, str(settings['capital_usage_ratio']))
            
            if 'donchian_activation_level' in settings:
                self.donchian_level_entry.delete(0, tk.END)
                self.donchian_level_entry.insert(0, str(settings['donchian_activation_level']))
            
            if 'hedge_enabled' in settings:
                self.hedge_var.set(settings['hedge_enabled'])
                
        except Exception as e:
            logger.warning(f"GUI 설정 적용 실패: {str(e)}")

    def run(self):
        """GUI 실행"""
        try:
            self.root.mainloop()
        finally:
            # GUI 종료 시 안전하게 스레드 정리
            if hasattr(self, 'trader') and self.trader:
                self.trader.stop()
            if hasattr(self, 'trading_thread') and self.trading_thread and self.trading_thread.is_alive():
                self.trading_thread.join(timeout=3)

def main():
    """메인 함수"""
    try:
        app = TradingGUI()
        app.run()
    except Exception as e:
        logger.error(f"프로그램 실행 오류: {str(e)}")
        messagebox.showerror("실행 오류", f"프로그램 실행 중 오류가 발생했습니다:\n{str(e)}")

if __name__ == "__main__":
    main()
                
