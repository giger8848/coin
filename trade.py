#!/usr/bin/env python
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import queue
import json
import os
import logging
import threading
from datetime import datetime
import ccxt
import pandas as pd
import time

# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MultiSymbolAutoTrader:
    """선물 거래를 위한 Donchian 채널 기반 매매 로직"""
    def __init__(self, settings, log_queue):
        self.settings = settings
        self.log_queue = log_queue
        self.running = False
        self.positions = {}

        # 거래소 초기화
        exchange_name = settings['selected_exchange'].lower()
        api_keys = settings['exchanges'][exchange_name]
        if exchange_name == 'okx':
            self.exchange = ccxt.okx({
                'apiKey': api_keys['api_key'],
                'secret': api_keys['secret_key'],
                'password': api_keys['password'],
                'enableRateLimit': True
            })
            # 서버 시간 동기화
            self.exchange.load_time_difference()
            time_diff = self.exchange.fetch_time() - self.exchange.milliseconds()
            self.exchange.options['timeDifference'] = time_diff
            self.exchange.load_markets()
            # 잔고 확인
            balance = self.exchange.fetch_balance(params={'type': 'future'})['total'].get('USDT', 0)
            self.log_queue.put(f"OKX 계정 잔고: {balance} USDT")
            # 최소 마진 확인 (추정치)
            required_margin = 100  # 임의의 최소 마진, 필요 시 조정
            if balance < required_margin:
                self.log_queue.put(f"경고: 계정 잔고 {balance} USDT가 최소 마진 {required_margin} USDT 미만입니다. 추가 입금 권장")
            # 레버리지 및 마진 모드 설정
            leverage = settings.get('leverage', 10)  # 기본값 10x로 증가
            if not 1 <= leverage <= 125:
                leverage = 10
                self.log_queue.put(f"OKX 레버리지 {settings.get('leverage')}가 유효 범위(1~125) 외입니다. 기본값 10x로 설정됨")
            for symbol in settings['symbols']:
                try:
                    market = self.exchange.market(symbol)
                    max_leverage = market.get('info', {}).get('leverageFilter', {}).get('maxLeverage', 125)
                    if isinstance(max_leverage, str):
                        max_leverage = int(float(max_leverage))
                    if leverage < 5:  # 최소 레버리지 5x로 가정
                        leverage = 5
                        self.log_queue.put(f"{symbol} 최소 레버리지 5x 미만입니다. 5x로 조정됨")
                    elif leverage > max_leverage:
                        leverage = max_leverage
                        self.log_queue.put(f"{symbol} 요청 레버리지 {settings['leverage']}x > 최대 {max_leverage}x, 조정됨")
                    self.exchange.set_leverage(leverage, symbol)
                    self.log_queue.put(f"{symbol} 레버리지 설정: {leverage}x")
                    self.exchange.set_margin_mode('isolated' if settings['hedge_enabled'] else 'cross', symbol=symbol, params={'lever': leverage})
                    self.log_queue.put(f"{symbol} 마진 모드 설정: {'isolated' if settings['hedge_enabled'] else 'cross'}")
                except Exception as e:
                    self.log_queue.put(f"{symbol} 레버리지/마진 설정 오류: {str(e)}")
                    try:
                        self.exchange.set_leverage(5, symbol)  # 최소 5x로 재시도
                        self.exchange.set_margin_mode('cross', symbol=symbol, params={'lever': 5})
                        self.positions[symbol] = {'size': 0, 'entry_price': 0}
                        self.log_queue.put(f"{symbol} 기본 레버리지 5x 및 크로스 마진으로 설정")
                    except Exception as ex:
                        self.log_queue.put(f"{symbol} 설정 실패: {str(ex)}")
                        raise
        elif exchange_name == 'binance':
            self.exchange = ccxt.binance({
                'apiKey': api_keys['api_key'],
                'secret': api_keys['secret_key'],
                'enableRateLimit': True,
                'options': {'defaultType': 'future'}
            })
            self.exchange.set_margin_mode('isolated' if settings['hedge_enabled'] else 'cross')
        elif exchange_name == 'bybit':
            self.exchange = ccxt.bybit({
                'apiKey': api_keys['api_key'],
                'secret': api_keys['secret_key'],
                'enableRateLimit': True,
                'options': {
                    'defaultContractType': 'linear',
                    'adjustForTimeDifference': True,
                    'recvWindow': 15000,
                    'timeDifference': 0
                }
            })
            if settings['hedge_enabled']:
                self.exchange.set_position_mode(True)
            self.exchange.set_margin_mode('isolated' if settings['hedge_enabled'] else 'cross', symbol=settings['symbols'][0])
        else:
            raise ValueError("지원하지 않는 거래소입니다")
        
        self.log_queue.put(f"Adjusted time difference: {time_diff}ms")
        self.log_queue.put(f"{exchange_name} 선물 거래소 연결 성공")

        # 나머지 심볼에 대한 레버리지 설정 (OKX에서는 위에서 처리)
        if exchange_name != 'okx':
            leverage = settings.get('leverage', 3)
            if not 1 <= leverage <= 125:
                leverage = 3
                self.log_queue.put(f"레버리지 {settings.get('leverage')}가 유효 범위(1~125) 외입니다. 기본값 3x로 설정됨")
            for symbol in settings['symbols']:
                if symbol not in self.exchange.symbols:
                    raise ValueError(f"유효하지 않은 거래 쌍: {symbol}")
                try:
                    market = self.exchange.market(symbol)
                    max_leverage = market.get('info', {}).get('leverageFilter', {}).get('maxLeverage', 100)
                    if isinstance(max_leverage, str):
                        max_leverage = int(float(max_leverage))
                    if leverage > max_leverage:
                        leverage = max_leverage
                        self.log_queue.put(f"{symbol} 요청 레버리지 {settings['leverage']}x > 최대 {max_leverage}x, 조정됨")
                    self.exchange.set_leverage(leverage, symbol)
                    self.positions[symbol] = {'size': 0, 'entry_price': 0}
                    self.log_queue.put(f"{symbol} 레버리지 설정: {leverage}x")
                except ValueError as ve:
                    self.log_queue.put(f"{symbol} 레버리지 설정 오류: {str(ve)}")
                    try:
                        self.exchange.set_leverage(1, symbol)
                        self.positions[symbol] = {'size': 0, 'entry_price': 0}
                        self.log_queue.put(f"{symbol} 기본 레버리지 1x로 설정")
                    except Exception as ex:
                        self.log_queue.put(f"{symbol} 레버리지 설정 실패: {str(ex)}")
                        raise
                except Exception as e:
                    self.log_queue.put(f"{symbol} 레버리지 설정 오류: {str(e)}")
                    try:
                        self.exchange.set_leverage(1, symbol)
                        self.positions[symbol] = {'size': 0, 'entry_price': 0}
                        self.log_queue.put(f"{symbol} 기본 레버리지 1x로 설정")
                    except Exception as ex:
                        self.log_queue.put(f"{symbol} 레버리지 설정 실패: {str(ex)}")
                        raise

    # 나머지 메서드 (fetch_ohlcv, calculate_donchian 등)는 변경 없음

    def get_price_precision(self, price, symbol=None):
            """가격과 심볼에 따른 적절한 소수점 자릿수 반환"""
            if symbol:
                try:
                    market = self.exchange.market(symbol)
                    precision = market.get('precision', {}).get('price', 8)  # 기본값 8
                    return precision
                except Exception:
                    pass  # 심볼 정보 없으면 기본 로직 사용
            # 기본 로직 (심볼 정보 없음)
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

    def format_price(self, price, symbol=None):
        """가격을 심볼에 맞는 소수점으로 포맷팅"""
        precision = self.get_price_precision(price, symbol)
        return f"${price:.{precision}f}"



    def fetch_ohlcv(self, symbol, timeframe='1h', limit=100):
        """OHLCV 데이터 가져오기"""
        # 요청 전 타임 차이 갱신
        time_diff = self.exchange.fetch_time() - self.exchange.milliseconds()
        self.exchange.options['timeDifference'] = time_diff
        self.log_queue.put(f"Request timestamp: {self.exchange.milliseconds()}, Server time: {self.exchange.fetch_time()}, Adjusted time difference: {time_diff}ms")
        try:
            ohlcv = self.exchange.fetch_ohlcv(symbol, timeframe, limit=limit)
            df = pd.DataFrame(ohlcv, columns=['timestamp', 'open', 'high', 'low', 'close', 'volume'])
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='ms')
            return df
        except Exception as e:
            self.log_queue.put(f"OHLCV 데이터 조회 오류 ({symbol}): {str(e)}")
            return None

    def calculate_donchian(self, symbol, df):
            """Donchian 채널 계산"""
            self.log_queue.put(f"Calculating Donchian for {symbol}")
            try:
                if df is None or df.empty:
                    self.log_queue.put(f"Donchian 계산 실패 ({symbol}): 데이터 없음")
                    return None
                period = self.settings.get('donchian_activation_level', 6)
                high_channel = df['high'].rolling(window=period).max()
                low_channel = df['low'].rolling(window=period).min()
                self.log_queue.put(f"Donchian calculated for {symbol}, high: {high_channel.iloc[-1]}, low: {low_channel.iloc[-1]}")
                return high_channel, low_channel
            except Exception as e:
                self.log_queue.put(f"Donchian 계산 오류 ({symbol}): {str(e)}")
                return None

    def get_balance(self):
        """계좌 잔고 조회 (선물 계정)"""
        try:
            balance = self.exchange.fetch_balance(params={'type': 'future'})['total'].get('USDT', 0)
            return balance
        except Exception as e:
            self.log_queue.put(f"잔고 조회 오류: {str(e)}")
            return 0

    def place_order(self, symbol, side, type, amount, price=None):
            """주문 생성"""
            self.log_queue.put(f"Placing {side} order for {symbol}, type: {type}, amount: {amount}, price: {price}")
            try:
                # 최소 주문 수량 확인
                market = self.exchange.market(symbol)
                min_amount = market.get('limits', {}).get('amount', {}).get('min', 0.01)
                self.log_queue.put(f"Minimum amount for {symbol}: {min_amount}")
                if amount < min_amount:
                    amount = min_amount
                    self.log_queue.put(f"Adjusted amount for {symbol} to minimum: {amount}")
                # 가격 정밀도 적용
                if price:
                    formatted_price = self.format_price(price, symbol)
                    self.log_queue.put(f"Formatted price for {symbol}: {formatted_price}")
                else:
                    formatted_price = None
                order = self.exchange.create_order(symbol, type, side, amount, formatted_price)
                self.log_queue.put(f"{symbol} {side} {type} 주문 성공: 계약수 {amount}")
                return order
            except Exception as e:
                self.log_queue.put(f"{symbol} 주문 오류: {str(e)}")
                return None

    def run(self):
        """매매 로직 실행"""
        self.running = True
        self.log_queue.put("자동매매가 시작되었습니다.")
        while self.running:
            for symbol in self.settings['symbols']:
                self.log_queue.put(f"Processing {symbol}")
                try:
                    df = self.fetch_ohlcv(symbol)
                    if df is None:
                        continue
                    channels = self.calculate_donchian(symbol, df)
                    if channels is None:
                        continue
                    high_channel, low_channel = channels
                    position = self.positions.get(symbol, {'size': 0})
                    if position['size'] == 0:
                        self.log_queue.put(f"{symbol} 포지션 없음, 초기 롱 시장가 진입")
                        order = self.place_order(symbol, 'buy', 'market', 0.05)  # 초기 수량
                        if order:
                            position['size'] = order['amount']
                            position['entry_price'] = order.get('average', df['close'].iloc[-1])
                            self.positions[symbol] = position
                except Exception as e:
                    self.log_queue.put(f"매매 로직 오류: {symbol}, {str(e)}")
                    continue
            time.sleep(60)

    def stop(self):
        """매매 중지"""
        self.running = False
        self.log_queue.put("매매 중지 요청")

    def emergency_stop(self):
        """긴급 정지: 모든 포지션 청산 및 미체결 주문 취소"""
        self.running = False
        try:
            for symbol in self.settings['symbols']:
                try:
                    self.exchange.cancel_all_orders(symbol)
                    self.log_queue.put(f"{symbol} 미체결 주문 취소")
                except Exception as e:
                    self.log_queue.put(f"{symbol} 미체결 주문 취소 오류: {str(e)}")
                
                position = self.positions[symbol]
                if position['size'] > 0:
                    self.place_order(symbol, 'sell', position['size'])
                    self.log_queue.put(f"{symbol} 롱 포지션 청산")
                elif position['size'] < 0:
                    self.place_order(symbol, 'buy', abs(position['size']))
                    self.log_queue.put(f"{symbol} 숏 포지션 청산")
                position['size'] = 0
                position['entry_price'] = 0
        except Exception as e:
            self.log_queue.put(f"긴급 정지 오류: {str(e)}")
        self.log_queue.put("긴급 정지 완료")

class TradingGUI:
    """기본형 GUI 인터페이스"""
    
    def __init__(self):
        self.trader = None
        self.trading_thread = None
        self.log_queue = queue.Queue()
        self.api_keys = {  # GUI에서 관리할 API 키 캐시
            'okx': {'api_key': '', 'secret_key': '', 'password': ''},
            'binance': {'api_key': '', 'secret_key': '', 'password': ''},
            'bybit': {'api_key': '', 'secret_key': '', 'password': ''}
        }
        
        self.root = tk.Tk()
        self.root.title("Crypto Futures Trading Bot")
        self.root.geometry("1000x700")
        
        self.setup_gui()
        self.load_settings()
        
        self.root.after(100, self.update_logs)

    def setup_gui(self):
        """GUI 레이아웃 설정"""
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        title_label = ttk.Label(main_frame, text="Futures Trading Bot", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        settings_frame = ttk.LabelFrame(main_frame, text="거래 설정")
        settings_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        self.notebook = ttk.Notebook(settings_frame)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.setup_api_tab()
        self.setup_trading_tab()
        
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill='x', pady=(0, 10))
        
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(side='left')
        
        self.start_btn = ttk.Button(button_frame, text="매매 시작", 
                                   command=self.start_trading, state='normal')
        self.start_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="매매 중지", 
                                  command=self.stop_trading, state='normal')
        self.stop_btn.pack(side='left', padx=5)
        
        self.emergency_btn = ttk.Button(button_frame, text="긴급 정지", 
                                       command=self.emergency_stop, state='normal')
        self.emergency_btn.pack(side='left', padx=5)
        
        self.status_label = ttk.Label(control_frame, text="상태: 대기 중")
        self.status_label.pack(side='right')
        
        log_frame = ttk.LabelFrame(main_frame, text="실시간 로그")
        log_frame.pack(fill='both', expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, 
                                                 font=('Consolas', 9))
        self.log_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.setup_menu()

    def setup_api_tab(self):
        """API 설정 탭"""
        api_frame = ttk.Frame(self.notebook)
        self.notebook.add(api_frame, text="API 설정")
        
        ttk.Label(api_frame, text="거래소 선택:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.exchange_var = tk.StringVar(value='Bybit')
        exchange_dropdown = ttk.Combobox(
            api_frame,
            textvariable=self.exchange_var,
            values=['OKX', 'Binance', 'Bybit'],
            state='readonly',
            width=47
        )
        exchange_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        exchange_dropdown.bind('<<ComboboxSelected>>', self.on_exchange_select)

        ttk.Label(api_frame, text="API Key:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.api_key_entry = ttk.Entry(api_frame, width=50, show='*')
        self.api_key_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        
        ttk.Label(api_frame, text="Secret Key:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.secret_key_entry = ttk.Entry(api_frame, width=50, show='*')
        self.secret_key_entry.grid(row=2, column=1, padx=5, pady=5, sticky='ew')
        
        ttk.Label(api_frame, text="Password:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.password_entry = ttk.Entry(api_frame, width=50, show='*')
        self.password_entry.grid(row=3, column=1, padx=5, pady=5, sticky='ew')

    def on_exchange_select(self, event):
        """드롭다운 선택 시 호출되는 콜백"""
        selected_exchange = self.exchange_var.get().lower()
        self.log_text.insert(tk.END, f"[INFO] 거래소 선택됨: {selected_exchange}\n")
        self.log_text.see(tk.END)
        # 저장된 API 키로 GUI 업데이트
        api_keys = self.api_keys.get(selected_exchange, {'api_key': '', 'secret_key': '', 'password': ''})
        self.api_key_entry.delete(0, tk.END)
        self.api_key_entry.insert(0, api_keys['api_key'])
        self.secret_key_entry.delete(0, tk.END)
        self.secret_key_entry.insert(0, api_keys['secret_key'])
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, api_keys['password'])
        # symbols 입력 필드 업데이트
        entries = [self.symbol1_entry, self.symbol2_entry, self.symbol3_entry]
        for entry in entries:
            symbol = entry.get().strip()
            if symbol:
                if selected_exchange == 'binance':
                    symbol = symbol.replace(':USDT', '')
                elif selected_exchange in ['okx', 'bybit'] and not symbol.endswith(':USDT'):
                    symbol = f"{symbol}:USDT"
                entry.delete(0, tk.END)
                entry.insert(0, symbol)

    def setup_trading_tab(self):
        """거래 설정 탭"""
        trading_frame = ttk.Frame(self.notebook)
        self.notebook.add(trading_frame, text="거래 설정")
        
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
        
        ttk.Label(trading_frame, text="레버리지:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.leverage_entry = ttk.Entry(trading_frame, width=20)
        self.leverage_entry.grid(row=1, column=1, sticky='w', padx=5, pady=5)
        self.leverage_entry.insert(0, "3")
        
        ttk.Label(trading_frame, text="익절 퍼센트 (%):").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.take_profit_entry = ttk.Entry(trading_frame, width=20)
        self.take_profit_entry.grid(row=2, column=1, sticky='w', padx=5, pady=5)
        self.take_profit_entry.insert(0, "1.0")
        
        ttk.Label(trading_frame, text="자본 사용 비율 (%):").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.capital_usage_entry = ttk.Entry(trading_frame, width=20)
        self.capital_usage_entry.grid(row=3, column=1, sticky='w', padx=5, pady=5)
        self.capital_usage_entry.insert(0, "50")  # 170%에서 50%로 안전하게 조정
        
        ttk.Label(trading_frame, text="손절허용 레벨:").grid(row=4, column=0, sticky='w', padx=5, pady=5)
        self.donchian_level_entry = ttk.Entry(trading_frame, width=20)
        self.donchian_level_entry.grid(row=4, column=1, sticky='w', padx=5, pady=5)
        self.donchian_level_entry.insert(0, "6")
        
        ttk.Label(trading_frame, text="헷지:").grid(row=5, column=0, sticky='w', padx=5, pady=5)
        self.hedge_var = tk.BooleanVar()
        self.hedge_checkbox = ttk.Checkbutton(trading_frame, variable=self.hedge_var)
        self.hedge_checkbox.grid(row=5, column=1, sticky='w', padx=5, pady=5)

    def setup_menu(self):
        """메뉴 설정"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="파일", menu=file_menu)
        file_menu.add_command(label="설정 저장", command=self.save_settings)
        file_menu.add_command(label="설정 불러오기", command=self.load_settings_file)
        file_menu.add_separator()
        file_menu.add_command(label="종료", command=self.root.quit)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="사용법", menu=help_menu)
        help_menu.add_command(label="최초 세팅 방법", command=self.show_initial_setup)
        help_menu.add_command(label="사용 설명서", command=self.show_user_manual)

    def show_initial_setup(self):
        """최초 세팅 방법 표시"""
        setup_text = """
=== 최초 세팅 방법 ===
1. 거래소 API 키 설정:
   - OKX, Binance, Bybit의 API 키, 시크릿 키, 패스워드(OKX 전용)를 준비하세요.
   - 'API 설정' 탭에서 거래소를 선택하고 키를 입력하거나, JSON 설정 파일을 불러오세요.
2. JSON 설정 파일:
   - '파일 > 설정 저장'으로 API 키와 거래 설정을 settings.json에 저장.
   - 예시: {"exchanges": {"okx": {"api_key": "...", "secret_key": "...", "password": "..."}, ...}, "selected_exchange": "OKX", ...}
   - '파일 > 설정 불러오기'로 저장된 설정을 불러옵니다.
3. 거래 설정:
   - 거래 종목(예: XRP/USDT:USDT), 레버리지, 익절 퍼센트, 자본 사용 비율, 손절허용 레벨 입력.
   - 헷지 모드 필요 시 체크.
4. 매매 시작:
   - 설정 완료 후 '매매 시작' 버튼 클릭.
        """
        self.show_text_window("최초 세팅 방법", setup_text)

    def show_user_manual(self):
        """사용 설명서 표시"""
        manual_text = """
=== 사용 설명서 ===
- Donchian 채널 기반 선물 거래 봇.
- 지원 거래소: OKX, Binance, Bybit (선물 전용).
- 매매 로직: 상단 채널 돌파 시 매수, 하단 이탈 또는 익절 시 매도.
- 헷지 모드: 활성화 시 숏 포지션 가능.
- 설정 저장/불러오기: API 키와 거래 설정을 JSON 파일로 관리.
- 긴급 정지: 모든 포지션 청산 및 미체결 주문 취소.
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

    def get_settings_from_gui(self):
        """GUI에서 설정 읽기"""
        try:
            symbols = []
            for entry in [self.symbol1_entry, self.symbol2_entry, self.symbol3_entry]:
                symbol = entry.get().strip()
                if symbol:
                    if self.exchange_var.get().lower() == 'binance':
                        symbol = symbol.replace(':USDT', '')
                    symbols.append(symbol)
            
            # 현재 GUI 입력값으로 API 키 업데이트
            selected_exchange = self.exchange_var.get().lower()
            self.api_keys[selected_exchange] = {
                'api_key': self.api_key_entry.get(),
                'secret_key': self.secret_key_entry.get(),
                'password': self.password_entry.get()
            }
            
            settings = {
                'exchanges': self.api_keys,
                'selected_exchange': self.exchange_var.get(),
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
                
                if not all([settings['exchanges'][settings['selected_exchange'].lower()]['api_key'],
                            settings['exchanges'][settings['selected_exchange'].lower()]['secret_key']]) or \
                (settings['selected_exchange'].lower() == 'okx' and not settings['exchanges']['okx']['password']):
                    messagebox.showerror("설정 오류", "API 키 정보를 모두 입력해주세요.")
                    return
                
                if not settings['symbols']:
                    messagebox.showerror("설정 오류", "거래할 종목을 최소 1개 이상 입력해주세요.")
                    return
                
                if settings['donchian_activation_level'] < 1 or settings['donchian_activation_level'] > 10:
                    messagebox.showerror("설정 오류", "손절허용 레벨은 1~10 사이의 값이어야 합니다.")
                    return
                
                if settings['capital_usage_ratio'] > 100:
                    messagebox.showwarning("경고", "자본 사용 비율이 100%를 초과합니다. 위험할 수 있습니다.")
                
                self.trader = MultiSymbolAutoTrader(settings, self.log_queue)
                self.trading_thread = threading.Thread(target=self.trader.run, daemon=False)
                self.trading_thread.start()
                
                self.start_btn.config(state='disabled')
                self.stop_btn.config(state='normal')
                self.emergency_btn.config(state='normal')
                self.status_label.config(text="상태: 매매 중")
                self.log_message("자동매매가 시작되었습니다.")
                
            except Exception as e:
                self.log_message(f"매매 시작 오류: {str(e)}")
                messagebox.showerror("시작 오류", f"매매 시작 중 오류가 발생했습니다:\n{str(e)}")
                # 오류 후 UI 상태 복구
                self.start_btn.config(state='normal')
                self.stop_btn.config(state='disabled')
                self.emergency_btn.config(state='disabled')

    def stop_trading(self):
        """매매 중지"""
        if self.trader:
            self.trader.stop()
            
            if self.trading_thread and self.trading_thread.is_alive():
                self.trading_thread.join(timeout=5)
            
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
            self.emergency_btn.config(state='disabled')
            self.status_label.config(text="상태: 중지됨")
            
            self.log_message("자동매매가 중지되었습니다.")

    def emergency_stop(self):
        """긴급 정지"""
        if self.trader:
            if messagebox.askyesno("긴급 정지", "모든 미체결 주문을 취소하고 포지션을 청산하시겠습니까?"):
                self.trader.emergency_stop()
                
                if self.trading_thread and self.trading_thread.is_alive():
                    self.trading_thread.join(timeout=10)
                
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
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(settings, f, indent=2, ensure_ascii=False)
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
            # API 키 캐시 업데이트
            if 'exchanges' in settings:
                for exchange in ['okx', 'binance', 'bybit']:
                    if exchange in settings['exchanges']:
                        self.api_keys[exchange] = settings['exchanges'][exchange]
            
            # 거래소 선택
            if 'selected_exchange' in settings:
                self.exchange_var.set(settings['selected_exchange'])
            
            # 거래 설정
            if 'symbols' in settings:
                symbols = settings['symbols']
                entries = [self.symbol1_entry, self.symbol2_entry, self.symbol3_entry]
                selected_exchange = self.exchange_var.get().lower()
                for i, entry in enumerate(entries):
                    entry.delete(0, tk.END)
                    if i < len(symbols):
                        symbol = symbols[i]
                        if selected_exchange == 'binance':
                            symbol = symbol.replace(':USDT', '')
                        elif selected_exchange in ['okx', 'bybit'] and not symbol.endswith(':USDT'):
                            symbol = f"{symbol}:USDT"
                        entry.insert(0, symbol)
            
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
            
            # API 키 필드 업데이트
            self.on_exchange_select(None)
            
        except Exception as e:
            logger.warning(f"GUI 설정 적용 실패: {str(e)}")

    def run(self):
        """GUI 실행"""
        try:
            self.root.mainloop()
        finally:
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
