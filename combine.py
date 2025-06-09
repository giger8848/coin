import ccxt
import tkinter as tk
from tkinter import ttk, messagebox
import json
import pandas as pd
import time
import logging
import threading
from datetime import datetime

# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# API 키 저장용 설정 파일
CONFIG_FILE = 'config.json'

class TradingBotGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("암호화폐 거래 봇")
        self.exchange = None
        self.symbol = 'BTC/USDT'  # 기본 거래 쌍
        self.timeframe = '1h'     # 기본 타임프레임
        self.amount = 0.001       # 기본 거래량 (BTC 기준)

        # GUI 요소 생성
        self.create_widgets()

        # 설정 로드
        self.config = self.load_config()

    def load_config(self):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                'OKX': {'apiKey': '', 'secret': '', 'password': ''},
                'Binance': {'apiKey': '', 'secret': ''},
                'Bybit': {'apiKey': '', 'secret': ''}
            }

    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4)

    def create_widgets(self):
        # 거래소 선택
        tk.Label(self.root, text="거래소 선택:").grid(row=0, column=0, padx=5, pady=5)
        self.exchange_var = tk.StringVar(value='OKX')
        exchange_dropdown = ttk.Combobox(self.root, textvariable=self.exchange_var, values=['OKX', 'Binance', 'Bybit'])
        exchange_dropdown.grid(row=0, column=1, padx=5, pady=5)

        # API 키
        tk.Label(self.root, text="API 키:").grid(row=1, column=0, padx=5, pady=5)
        self.api_key_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.api_key_var, width=30).grid(row=1, column=1, padx=5, pady=5)

        # API 비밀키
        tk.Label(self.root, text="API 비밀키:").grid(row=2, column=0, padx=5, pady=5)
        self.api_secret_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.api_secret_var, width=30, show='*').grid(row=2, column=1, padx=5, pady=5)

        # API 패스프레이즈 (OKX 전용)
        tk.Label(self.root, text="API 패스프레이즈 (OKX 전용):").grid(row=3, column=0, padx=5, pady=5)
        self.api_passphrase_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.api_passphrase_var, width=30, show='*').grid(row=3, column=1, padx=5, pady=5)

        # 거래 쌍
        tk.Label(self.root, text="거래 쌍 (예: BTC/USDT):").grid(row=4, column=0, padx=5, pady=5)
        self.symbol_var = tk.StringVar(value=self.symbol)
        tk.Entry(self.root, textvariable=self.symbol_var, width=30).grid(row=4, column=1, padx=5, pady=5)

        # 거래량
        tk.Label(self.root, text="거래량 (기본 통화 기준):").grid(row=5, column=0, padx=5, pady=5)
        self.amount_var = tk.DoubleVar(value=self.amount)
        tk.Entry(self.root, textvariable=self.amount_var, width=30).grid(row=5, column=1, padx=5, pady=5)

        # 시작 버튼
        tk.Button(self.root, text="거래 시작", command=self.start_trading).grid(row=6, column=0, columnspan=2, pady=10)

        # 중지 버튼
        tk.Button(self.root, text="거래 중지", command=self.stop_trading).grid(row=7, column=0, columnspan=2, pady=10)

        self.running = False

    def initialize_exchange(self):
        exchange_name = self.exchange_var.get().lower()
        api_key = self.api_key_var.get()
        api_secret = self.api_secret_var.get()
        api_passphrase = self.api_passphrase_var.get()

        # 설정 업데이트
        self.config[self.exchange_var.get()] = {
            'apiKey': api_key,
            'secret': api_secret,
            'password': api_passphrase if exchange_name == 'okx' else ''
        }
        self.save_config()

        try:
            if exchange_name == 'okx':
                self.exchange = ccxt.okx({
                    'apiKey': api_key,
                    'secret': api_secret,
                    'password': api_passphrase,
                    'enableRateLimit': True
                })
            elif exchange_name == 'binance':
                self.exchange = ccxt.binance({
                    'apiKey': api_key,
                    'secret': api_secret,
                    'enableRateLimit': True
                })
            elif exchange_name == 'bybit':
                self.exchange = ccxt.bybit({
                    'apiKey': api_key,
                    'secret': api_secret,
                    'enableRateLimit': True
                })
            else:
                raise ValueError("지원하지 않는 거래소입니다")
            
            self.exchange.load_markets()
            logger.info(f"{exchange_name} 거래소에 연결되었습니다")
            return True
        except Exception as e:
            messagebox.showerror("에러", f"{exchange_name} 연결 실패: {str(e)}")
            logger.error(f"거래소 연결 실패: {str(e)}")
            return False

    def fetch_ohlcv(self):
        try:
            ohlcv = self.exchange.fetch_ohlcv(self.symbol, self.timeframe, limit=100)
            df = pd.DataFrame(ohlcv, columns=['timestamp', 'open', 'high', 'low', 'close', 'volume'])
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='ms')
            return df
        except Exception as e:
            logger.error(f"OHLCV 데이터 조회 에러: {str(e)}")
            return None

    def calculate_rsi(self, data, periods=14):
        delta = data['close'].diff()
        gain = (delta.where(delta > 0, 0)).rolling(window=periods).mean()
        loss = (-delta.where(delta < 0, 0)).rolling(window=periods).mean()
        rs = gain / loss
        return 100 - (100 / (1 + rs))

    def place_order(self, side, amount):
        try:
            if side == 'buy':
                order = self.exchange.create_market_buy_order(self.symbol, amount)
            elif side == 'sell':
                order = self.exchange.create_market_sell_order(self.symbol, amount)
            logger.info(f"{side} 주문 실행: {order}")
            return order
        except Exception as e:
            logger.error(f"{side} 주문 실행 에러: {str(e)}")
            return None

    def trading_strategy(self):
        while self.running:
            df = self.fetch_ohlcv()
            if df is None:
                time.sleep(60)
                continue

            # RSI 계산
            df['rsi'] = self.calculate_rsi(df)
            latest_rsi = df['rsi'].iloc[-1]
            latest_price = df['close'].iloc[-1]

            # 거래 로직 (RSI 기반 예시)
            if latest_rsi < 30:  # 과매도
                logger.info(f"RSI {latest_rsi:.2f} < 30, {latest_price}에서 매수")
                self.place_order('buy', self.amount)
            elif latest_rsi > 70:  # 과매수
                logger.info(f"RSI {latest_rsi:.2f} > 70, {latest_price}에서 매도")
                self.place_order('sell', self.amount)

            time.sleep(60)  # 1분 대기

    def start_trading(self):
        if not self.initialize_exchange():
            return

        self.symbol = self.symbol_var.get()
        self.amount = self.amount_var.get()

        if not self.symbol in self.exchange.symbols:
            messagebox.showerror("에러", f"잘못된 거래 쌍: {self.symbol}")
            return

        self.running = True
        self.root.title(f"암호화폐 거래 봇 - {self.exchange_var.get()}에서 실행 중")
        threading.Thread(target=self.trading_strategy, daemon=True).start()
        messagebox.showinfo("정보", "거래가 시작되었습니다")

    def stop_trading(self):
        self.running = False
        self.root.title("암호화폐 거래 봇")
        messagebox.showinfo("정보", "거래가 중지되었습니다")

def main():
    root = tk.Tk()
    app = TradingBotGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()