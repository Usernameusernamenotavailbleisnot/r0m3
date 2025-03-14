import requests
import time
import random
from twocaptcha import TwoCaptcha
import capsolver
from eth_account import Account
import json
from web3 import Web3
import datetime
import solcx
from colorama import init, Fore, Back, Style
from abc import ABC, abstractmethod

init(autoreset=True)
EXPLORER_URL = "https://node2.testnet.romeprotocol.xyz:1000/tx/"

# Token lists for random token generation
MEME_TOKENS = [
    # Classic Meme Tokens
    "PEPE", "DOGE", "SHIB", "FLOKI", "WOJAK", "BONK", "CHEEMS",
    "CATE", "MOCHI", "KISHU", "SAMO", "HOGE", "TOSHI", "ELON",
    
    # Animal-themed
    "PUPPY", "KITTY", "PANDA", "KOALA", "FROG", "HAMSTER", "RABBIT",
    "MONKEY", "GOAT", "TIGER", "LION", "DRAGON", "WHALE", "SHARK",
    
    # Popular Internet Memes
    "WOJAK", "PEPO", "DOGO", "MOON", "CHAD", "STONK", "MUSK",
    "COIN", "TENDIES", "APE", "ALPHA", "BETA", "SIGMA", "LAMBO",
    
    # Food-themed
    "SUSHI", "PIZZA", "TACO", "BURGER", "NOODLE", "RAMEN", "CURRY",
    
    # Tech-themed
    "CYBER", "PIXEL", "CRYPTO", "BLOCK", "CHAIN", "TOKEN", "META",
    
    # Fun/Random
    "YOLO", "FOMO", "GEM", "STAR", "SMART", "KING", "QUEEN", "ACE",
    "DIAMOND", "GOLD", "SILVER", "PLAT", "RUBY", "EMBER"
]

class CaptchaSolver(ABC):
    @abstractmethod
    def solve_recaptcha(self, sitekey, url):
        pass

class TwoCaptchaSolver(CaptchaSolver):
    def __init__(self, api_key):
        self.solver = TwoCaptcha(api_key)
        
    def solve_recaptcha(self, sitekey, url):
        result = self.solver.recaptcha(
            sitekey=sitekey,
            url=url
        )
        return result['code']

class CapsolverSolver(CaptchaSolver):
    def __init__(self, api_key):
        capsolver.api_key = api_key
        
    def solve_recaptcha(self, sitekey, url):
        try:
            solution = capsolver.solve({
                "type": "ReCaptchaV2TaskProxyless",
                "websiteURL": url,
                "websiteKey": sitekey,
                "fallbackTimeout": 180
            })
            
            if isinstance(solution, dict) and 'gRecaptchaResponse' in solution:
                return solution['gRecaptchaResponse']
            elif 'solution' in solution and 'gRecaptchaResponse' in solution['solution']:
                return solution['solution']['gRecaptchaResponse']
            else:
                print(f"{Fore.YELLOW}[*] Unexpected Capsolver response structure: {solution}{Style.RESET_ALL}")
                raise ValueError("Invalid response structure from Capsolver")
                
        except Exception as e:
            print(f"{Fore.RED}[!] Capsolver error: {str(e)}{Style.RESET_ALL}")
            raise

class RomeProtocol:
    def __init__(self):
        self.config = self.load_config()
        self.w3 = Web3(Web3.HTTPProvider('https://rome.testnet.romeprotocol.xyz'))
        self.chain_id = 200018
        self.setup_captcha_solver()
        print(f"{Fore.CYAN}[*] Initializing Rome Protocol...{Style.RESET_ALL}")
        solcx.install_solc('0.8.26')
        
        # Contract addresses
        self.router_address = "0x3696d3bc61E78e8EC9E8A35865c6681d7Dd0c49d"
        self.token_addresses = {
            'WETH': '0x33932D72AA77E1De7cB173bB88C46080c731Dd39',
            'ETH': '0x602257c76C8461b39A48C46ef1Cb587AE30AEFD0',
            'SOL': '0x7e12712c7567468a7920472d10766e6b539943FB',
            'USDC': '0x99901Dba00118c726E741066cA45Da1Ce8b66e0d'
        }

        # Contract templates
        self.contract_source = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;
contract HelloWorld {
    string public greet = "Hello World!";
}
'''

        self.token_source = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract MemeToken {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor(string memory _name, string memory _symbol, uint8 _decimals, uint256 _totalSupply) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        totalSupply = _totalSupply;
        balanceOf[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }
    
    function transfer(address to, uint256 value) public returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }
    
    function approve(address spender, uint256 value) public returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Insufficient allowance");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;
        emit Transfer(from, to, value);
        return true;
    }
}
'''

    def load_config(self):
        try:
            with open('config.json', 'r') as f:
                config = json.load(f)
                
            default_config = {
                'enable_faucet': True,
                'enable_contract_deploy': True,
                'enable_token_deploy': True,
                'enable_swap': True,
                'swap_settings': {
                    'tokens': {
                        'ETH': {
                            'swaps': 2,
                            'amount_type': 'fixed',
                            'amount': 0.01,
                            'min_amount': 0.01,
                            'max_amount': 0.02
                        },
                        'SOL': {
                            'swaps': 3,
                            'amount_type': 'random',
                            'min_amount': 0.01,
                            'max_amount': 0.02
                        },
                        'USDC': {
                            'swaps': 1,
                            'amount_type': 'fixed',
                            'amount': 0.015
                        }
                    }
                },
                'faucet_amount': '0.1',
                '2captcha_key': '',
                'capsolver_key': ''
            }
            
            # Merge default config with loaded config
            for key, value in default_config.items():
                if key not in config:
                    config[key] = value
                elif isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        if sub_key not in config[key]:
                            config[key][sub_key] = sub_value
            
            print(f"{Fore.GREEN}[+] Config loaded successfully{Style.RESET_ALL}")
            return config
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading config: {e}{Style.RESET_ALL}")
            raise

    def setup_captcha_solver(self):
        twocaptcha_key = self.config.get('2captcha_key', '').strip()
        capsolver_key = self.config.get('capsolver_key', '').strip()
        if capsolver_key:
            print(f"{Fore.GREEN}[+] Using Capsolver service{Style.RESET_ALL}")
            self.captcha_solver = CapsolverSolver(capsolver_key)
        elif twocaptcha_key:
            print(f"{Fore.GREEN}[+] Using 2captcha service{Style.RESET_ALL}")
            self.captcha_solver = TwoCaptchaSolver(twocaptcha_key)
        else:
            raise ValueError("No valid captcha service API key found in config")

    def get_wallets(self):
        wallets = []
        try:
            with open('pk.txt', 'r') as f:
                for line in f:
                    pk = line.strip()
                    if pk:
                        account = Account.from_key(pk)
                        wallets.append({
                            'address': account.address,
                            'private_key': pk
                        })
            print(f"{Fore.GREEN}[+] Loaded {len(wallets)} wallets{Style.RESET_ALL}")
            return wallets
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading wallets: {e}{Style.RESET_ALL}")
            return []

    def solve_captcha(self):
        solver_name = "Capsolver" if isinstance(self.captcha_solver, CapsolverSolver) else "2captcha"
        print(f"{Fore.YELLOW}[*] Solving captcha using {solver_name}...{Style.RESET_ALL}")
        try:
            result = self.captcha_solver.solve_recaptcha(
                sitekey='6Leq7o0qAAAAAKC0I6TptEAo6QxUcbv7_WFA1Ly9',
                url='https://rome.testnet.romeprotocol.xyz/airdrop'
            )
            print(f"{Fore.GREEN}[+] Captcha solved successfully{Style.RESET_ALL}")
            return result
        except Exception as e:
            print(f"{Fore.RED}[!] Error solving captcha: {e}{Style.RESET_ALL}")
            return None

    def claim_airdrop(self, wallet_address):
        if not self.config['enable_faucet']:
            print(f"{Fore.YELLOW}[*] Faucet claiming is disabled in config{Style.RESET_ALL}")
            return None
            
        print(f"{Fore.CYAN}[*] Attempting airdrop claim for {wallet_address[:8]}...{Style.RESET_ALL}")
        captcha = self.solve_captcha()
        if not captcha:
            return None
        payload = {
            "recipientAddr": wallet_address,
            "amount": str(self.config.get('faucet_amount', '0.1')),
            "captchaResponse": captcha
        }
        
        try:
            response = requests.post('https://rome.testnet.romeprotocol.xyz/airdrop', json=payload)
            try:
                result = response.json()
                if result.get('success'):
                    print(f"{Fore.GREEN}[+] Airdrop claimed successfully! > {result}{Style.RESET_ALL}")
                    if 'hash' in result:
                        explorer_url = f"{EXPLORER_URL}{result['hash']}"
                        print(f"{Fore.GREEN}[+] Explorer URL: {explorer_url}{Style.RESET_ALL}")
                        result['explorer_url'] = explorer_url
                else:
                    print(f"{Fore.RED}[!] Airdrop claim failed > {result}{Style.RESET_ALL}")
                return result
            except ValueError as e:
                print(f"{Fore.RED}[!] Failed to parse JSON response: {str(e)}{Style.RESET_ALL}")
                return {
                    'success': False,
                    'error': 'Invalid JSON response',
                    'raw_response': response.text
                }
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error claiming airdrop: {str(e)}{Style.RESET_ALL}")
            return {
                'success': False,
                'error': str(e)
            }

    def compile_contract(self):
        compiled_sol = solcx.compile_source(
            self.contract_source,
            output_values=['abi', 'bin'],
            solc_version='0.8.26'
        )
        contract_interface = compiled_sol['<stdin>:HelloWorld']
        return contract_interface['abi'], contract_interface['bin']

    def deploy_contract(self, wallet):
        if not self.config['enable_contract_deploy']:
            print(f"{Fore.YELLOW}[*] Contract deployment is disabled in config{Style.RESET_ALL}")
            return None
            
        print(f"{Fore.CYAN}[*] Deploying HelloWorld contract from {wallet['address'][:8]}...{Style.RESET_ALL}")
        try:
            abi, bytecode = self.compile_contract()
            if not bytecode.startswith('0x'):
                bytecode = '0x' + bytecode

            contract = self.w3.eth.contract(abi=abi, bytecode=bytecode)
            nonce = self.w3.eth.get_transaction_count(wallet['address'])
            
            print(f"{Fore.YELLOW}[*] Estimating gas...{Style.RESET_ALL}")
            gas_estimate = contract.constructor().estimate_gas({
                'from': wallet['address']
            })
            
            transaction = {
                'from': wallet['address'],
                'nonce': nonce,
                'gas': gas_estimate,
                'gasPrice': self.w3.eth.gas_price,
                'chainId': self.chain_id,
                'data': bytecode
            }

            signed = self.w3.eth.account.sign_transaction(transaction, wallet['private_key'])
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            
            print(f"{Fore.YELLOW}[*] Waiting for contract deployment confirmation...{Style.RESET_ALL}")
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            explorer_url = f"{EXPLORER_URL}{tx_hash.hex()}"
            print(f"{Fore.GREEN}[+] Contract deployed successfully!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Contract address: {receipt.contractAddress}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Explorer URL: {explorer_url}{Style.RESET_ALL}")

            return {
                'success': True,
                'contract_address': receipt.contractAddress,
                'transaction_hash': tx_hash.hex(),
                'explorer_url': explorer_url
            }
        except Exception as e:
            print(f"{Fore.RED}[!] Contract deployment failed: {e}{Style.RESET_ALL}")
            return {
                'success': False,
                'error': str(e)
            }

    def generate_token_name(self):
        base_name = random.choice(MEME_TOKENS)
        suffix = random.choice([
            "INU", "MOON", "ROCKET", "FARM", "SAFE", "BASED",
            "LAUNCH", "RISE", "PUMP", "BURST", "DASH", "RUSH",
            "ELITE", "PRIME", "ULTRA", "SUPER", "MEGA", "HYPER",
            "AI", "BOT", "SWAP", "DEX", "NFT", "DAO", "DEFI",
            "X", "VERSE", "WORLD", "ZONE", "HUB", "PORT", "NET"
        ])
        
        # Format name with space: "STONK AI" instead of "STONKAI"
        token_name = f"{base_name} {suffix}"
        
        # Format symbol by combining without space: "STONKAI"
        token_symbol = f"{base_name}{suffix}"
        
        return token_name, token_symbol

    def compile_token_contract(self):
        compiled_sol = solcx.compile_source(
            self.token_source,
            output_values=['abi', 'bin'],
            solc_version='0.8.26'
        )
        contract_interface = compiled_sol['<stdin>:MemeToken']
        return contract_interface['abi'], contract_interface['bin']

    def deploy_token(self, wallet):
        if not self.config['enable_token_deploy']:
            print(f"{Fore.YELLOW}[*] Token deployment is disabled in config{Style.RESET_ALL}")
            return None
            
        print(f"{Fore.CYAN}[*] Deploying token from {wallet['address'][:8]}...{Style.RESET_ALL}")
        try:
            token_name, token_symbol = self.generate_token_name()
            decimals = 18
            total_supply = 1000000000 * (10 ** decimals)  # 1 billion tokens

            abi, bytecode = self.compile_token_contract()
            if not bytecode.startswith('0x'):
                bytecode = '0x' + bytecode
                
            contract = self.w3.eth.contract(abi=abi, bytecode=bytecode)
            
            print(f"{Fore.YELLOW}[*] Token Details:{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Name: {token_name}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Symbol: {token_symbol}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Total Supply: 1,000,000,000{Style.RESET_ALL}")

            nonce = self.w3.eth.get_transaction_count(wallet['address'])
            
            construct_txn = contract.constructor(token_name, token_symbol, decimals, total_supply).build_transaction({
                'from': wallet['address'],
                'nonce': nonce,
                'gas': 3000000,
                'gasPrice': self.w3.eth.gas_price,
                'chainId': self.chain_id
            })

            signed = self.w3.eth.account.sign_transaction(construct_txn, wallet['private_key'])
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            
            print(f"{Fore.YELLOW}[*] Waiting for token deployment confirmation...{Style.RESET_ALL}")
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            explorer_url = f"{EXPLORER_URL}{tx_hash.hex()}"
            print(f"{Fore.GREEN}[+] Token deployed successfully!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Contract address: {receipt.contractAddress}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Explorer URL: {explorer_url}{Style.RESET_ALL}")

            return {
                'success': True,
                'token_name': token_name,
                'token_symbol': token_symbol,
                'contract_address': receipt.contractAddress,
                'transaction_hash': tx_hash.hex(),
                'explorer_url': explorer_url
            }
        except Exception as e:
            print(f"{Fore.RED}[!] Token deployment failed: {e}{Style.RESET_ALL}")
            return {
                'success': False,
                'error': str(e)
            }

    def get_swap_amount(self, token_settings):
        """Get swap amount based on token-specific settings with decimal precision control"""
        if token_settings['amount_type'] == 'fixed':
            return token_settings['amount']
        else:
            # Get random float between min and max
            raw_amount = random.uniform(token_settings['min_amount'], token_settings['max_amount'])
            # Round to specified decimal places
            decimals = token_settings.get('decimals', 4)  # Default to 4 decimals if not specified
            return round(raw_amount, decimals)

    def perform_swaps(self, wallet):
        """Perform multiple swaps according to configuration"""
        if not self.config['enable_swap']:
            print(f"{Fore.YELLOW}[*] Swap functionality is disabled in config{Style.RESET_ALL}")
            return []

        swap_results = []
        token_settings = self.config['swap_settings']['tokens']

        for token_symbol, settings in token_settings.items():
            num_swaps = settings.get('swaps', 1)
            print(f"{Fore.CYAN}[*] Processing {num_swaps} swaps for {token_symbol}{Style.RESET_ALL}")
            
            for swap_num in range(num_swaps):
                print(f"{Fore.CYAN}[*] Performing swap {swap_num + 1}/{num_swaps} for {token_symbol}{Style.RESET_ALL}")
                
                # Get fresh balance before swap
                current_balance = self.check_balance(wallet['address'])
                if current_balance < 0.001:
                    print(f"{Fore.RED}[!] Insufficient balance for swap{Style.RESET_ALL}")
                    break
                    
                swap_result = self.swap_tokens(wallet, token_symbol, settings)
                if swap_result:
                    swap_results.append(swap_result)
                    print(f"{Fore.YELLOW}[*] Waiting 10 seconds before next swap...{Style.RESET_ALL}")
                    time.sleep(10)
                else:
                    print(f"{Fore.RED}[!] Swap failed, skipping remaining swaps for {token_symbol}{Style.RESET_ALL}")
                    break

        return swap_results

    def swap_tokens(self, wallet, token_symbol, token_settings):
        """Execute a single swap with the specified settings"""
        print(f"{Fore.CYAN}[*] Attempting to swap ROME for {token_symbol} from {wallet['address'][:8]}...{Style.RESET_ALL}")
        
        try:
            amount = self.get_swap_amount(token_settings)
            amount_wei = Web3.to_wei(amount, 'ether')
            
            path = [
                self.token_addresses['WETH'],
                self.token_addresses[token_symbol]
            ]
            
            router_abi = [
                {
                    "inputs": [
                        {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
                        {"internalType": "address[]", "name": "path", "type": "address[]"},
                        {"internalType": "address", "name": "to", "type": "address"},
                        {"internalType": "uint256", "name": "deadline", "type": "uint256"}
                    ],
                    "name": "swapExactETHForTokens",
                    "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
                    "stateMutability": "payable",
                    "type": "function"
                }
            ]
            
            router = self.w3.eth.contract(address=self.router_address, abi=router_abi)
            deadline = int(time.time()) + 1200
            nonce = self.w3.eth.get_transaction_count(wallet['address'])
            min_out = 0
            
            print(f"{Fore.YELLOW}[*] Estimating gas for swap...{Style.RESET_ALL}")
            gas_estimate = router.functions.swapExactETHForTokens(
                min_out,
                path,
                wallet['address'],
                deadline
            ).estimate_gas({
                'from': wallet['address'],
                'value': amount_wei
            })
            print(f"{Fore.YELLOW}[*] Gas estimate: {gas_estimate}{Style.RESET_ALL}")
            
            transaction = router.functions.swapExactETHForTokens(
                min_out,
                path,
                wallet['address'],
                deadline
            ).build_transaction({
                'from': wallet['address'],
                'value': amount_wei,
                'gas': gas_estimate,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': nonce,
                'chainId': self.chain_id
            })
            
            signed_txn = self.w3.eth.account.sign_transaction(transaction, wallet['private_key'])
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
            
            print(f"{Fore.YELLOW}[*] Waiting for swap confirmation...{Style.RESET_ALL}")
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            explorer_url = f"{EXPLORER_URL}{tx_hash.hex()}"
            print(f"{Fore.GREEN}[+] Swap completed successfully!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Explorer URL: {explorer_url}{Style.RESET_ALL}")
            
            return {
                'success': True,
                'transaction_hash': tx_hash.hex(),
                'explorer_url': explorer_url,
                'amount': amount,
                'token': token_symbol
            }
            
        except Exception as e:
            print(f"{Fore.RED}[!] Swap failed: {e}{Style.RESET_ALL}")
            return {
                'success': False,
                'error': str(e)
            }

    def check_balance(self, address):
        print(f"{Fore.YELLOW}[*] Checking balance for {address[:8]}...{Style.RESET_ALL}")
        try:
            balance = self.w3.eth.get_balance(address)
            balance_eth = Web3.from_wei(balance, 'ether')
            print(f"{Fore.CYAN}[*] Balance: {balance_eth} ROME{Style.RESET_ALL}")
            return balance_eth
        except Exception as e:
            print(f"{Fore.RED}[!] Error checking balance: {e}{Style.RESET_ALL}")
            return 0

    def log_result(self, wallet_address, airdrop_result, contract_result=None, token_result=None, swap_results=None):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            'timestamp': timestamp,
            'wallet': wallet_address,
            'airdrop': airdrop_result,
            'contract_deployment': contract_result,
            'token_deployment': token_result,
            'swaps': swap_results
        }
        
        try:
            with open('results.json', 'a') as f:
                json.dump(log_entry, f, indent=2)
                f.write('\n')
            print(f"{Fore.GREEN}[+] Results logged successfully{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error logging results: {e}{Style.RESET_ALL}")

    def run(self):
        print(f"\n{Back.BLUE}{Fore.WHITE} Rome Protocol Bot Started {Style.RESET_ALL}\n")
        while True:
            wallets = self.get_wallets()
            
            for wallet in wallets:
                print(f"\n{Back.CYAN}{Fore.BLACK} Processing Wallet {wallet['address'][:8]}... {Style.RESET_ALL}")
                current_balance = self.check_balance(wallet['address'])
                
                # Initialize results
                airdrop_result = None
                contract_result = None
                token_result = None
                swap_results = []
                
                # Try to claim faucet if enabled
                if self.config['enable_faucet']:
                    print(f"{Fore.CYAN}[*] Attempting to claim faucet...{Style.RESET_ALL}")
                    airdrop_result = self.claim_airdrop(wallet['address'])
                    if airdrop_result and airdrop_result.get('success'):
                        print(f"{Fore.GREEN}[+] Waiting 30 seconds for faucet transaction to confirm...{Style.RESET_ALL}")
                        time.sleep(30)
                        current_balance = self.check_balance(wallet['address'])
                    else:
                        print(f"{Fore.RED}[!] Faucet claim failed{Style.RESET_ALL}")
                
                # Check balance for other operations
                if current_balance >= 0.001:
                    print(f"{Fore.GREEN}[+] Sufficient balance for operations{Style.RESET_ALL}")
                    
                    # Deploy contract if enabled
                    if self.config['enable_contract_deploy']:
                        contract_result = self.deploy_contract(wallet)
                        if contract_result and contract_result.get('success'):
                            print(f"{Fore.YELLOW}[*] Waiting 10 seconds before next operation...{Style.RESET_ALL}")
                            time.sleep(10)
                    
                    # Deploy token if enabled
                    if self.config['enable_token_deploy']:
                        token_result = self.deploy_token(wallet)
                        if token_result and token_result.get('success'):
                            print(f"{Fore.YELLOW}[*] Waiting 10 seconds before next operation...{Style.RESET_ALL}")
                            time.sleep(10)
                    
                    # Perform multiple swaps if enabled
                    if self.config['enable_swap']:
                        swap_results = self.perform_swaps(wallet)
                else:
                    print(f"{Fore.YELLOW}[!] Insufficient balance for operations{Style.RESET_ALL}")
                
                # Log results
                self.log_result(
                    wallet['address'],
                    airdrop_result,
                    contract_result,
                    token_result,
                    swap_results
                )
                
                print(f"{Fore.YELLOW}[*] Waiting 5 seconds before next wallet...{Style.RESET_ALL}")
                time.sleep(5)
            
            print(f"\n{Back.YELLOW}{Fore.BLACK} Waiting 7 hours before next round... {Style.RESET_ALL}")
            time.sleep(7 * 60 * 60)

if __name__ == "__main__":
    try:
        print(f"\n{Back.GREEN}{Fore.BLACK} Starting Rome Protocol Bot {Style.RESET_ALL}")
        rome = RomeProtocol()
        rome.run()
    except KeyboardInterrupt:
        print(f"\n{Back.RED}{Fore.WHITE} Bot stopped by user {Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Back.RED}{Fore.WHITE} Fatal error: {e} {Style.RESET_ALL}")
        # Log the error to a file
        with open('error_log.txt', 'a') as f:
            f.write(f"\n[{datetime.datetime.now()}] Fatal error: {str(e)}")
        raise
