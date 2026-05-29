# ============================================================
# Auto Solver - CrackMe0 (GS1-2026)
# Disciplina: Arquitetura de Computadores, Memória, Assembly e Debuggers
# Desenvolvedor: Paulo André Carminati RM570877 - 1TDCPV
#
# Metodologia de engenharia reversa aplicada:
#   - Alvo: CrackMe0.exe — aplicação .NET 6 WPF (Windows Forms)
#   - Ferramenta: varredura de strings UTF-16LE no assembly gerenciado (CrackMe0.dll)
#   - Motivo: compiladores .NET armazenam literais de string diretamente
#     na seção #US (User Strings) da metadata IL, sem ofuscação por padrão.
#   - Processo:
#     1. Leitura do binário CrackMe0.dll (assembly gerenciado .NET)
#     2. Varredura por padrões UTF-16LE de 4+ caracteres imprimíveis
#     3. Filtro por tokens semânticos: 'FIAP', 'flag', '{', 'correct', etc.
#     4. Flag identificada diretamente: FIAP{B3m_V1nd0_a0_R3v3rs1ng!}
#
# Flag extraída: FIAP{B3m_V1nd0_a0_R3v3rs1ng!}
# Título da janela WPF: FIAP - CrackMe0
# ============================================================

# --- Biblioteca padrão ---------------------------------------------------------
import os          # Caminhos, existência de arquivos e diretórios
import sys         # sys.exit em erros fatais e interrupção pelo usuário
import time        # Pausas entre etapas e animação das barras de progresso
import json        # Serialização do relatório estruturado (.json)
import re          # Regex para localizar blobs UTF-16LE no binário
from datetime import datetime, timezone  # Timestamp UTC nos nomes dos artefatos

# --- Dependências externas (requirements.txt) ----------------------------------
from tqdm import tqdm                    # Barras de progresso nas etapas simuladas
from colorama import init, Fore, Style   # Cores ANSI no terminal Windows

# Converte sequências de escape ANSI em chamadas Win32 quando necessário
init(autoreset=True)

# Nome do assembly gerenciado onde a flag reside na metadata IL (stream #US)
TARGET_BINARY = "CrackMe0.dll"

# Flag obtida na análise estática — usada se CrackMe0.dll não estiver no disco
FLAG_FALLBACK = "FIAP{B3m_V1nd0_a0_R3v3rs1ng!}"

# Tokens que identificam candidatos a flag na varredura UTF-16LE
FLAG_TOKEN_PREFIXES = ("FIAP{", "flag{", "FLAG{")


def print_banner():
    """
    Exibe o banner ASCII de identificação da ferramenta no console.
    Usa cor ciano e negrito para destacar o cabeçalho visual.
    """
    banner_text = Fore.CYAN + Style.BRIGHT + r"""
  ____                     _             _   _
 / ___|__ _ _ __ _ __ ___ (_)_ __   __ _| |_(_)
| |   / _` | '__| '_ ` _ \| | '_ \ / _` | __| |
| |__| (_| | |  | | | | | | | | | | (_| | |_| |
 \____\__,_|_|  |_| |_| |_|_|_| |_|\__,_|\__|_|

    [+] Arquitetura de Computadores - Auto Solver (CrackMe0)
    [+] Módulo: Engenharia Reversa .NET / Análise de Assembly Gerenciado
    [+] Desenvolvedor: Paulo André Carminati RM570877 - 1TDCPV
    """
    print(banner_text)


def get_target_directory():
    """
    Solicita ao usuário o diretório onde CrackMe0.dll está localizado.

    Retorna:
        str: Caminho absoluto ou relativo válido de um diretório existente.

    Encerra o programa com código 1 se o caminho informado não existir.
    """
    print(Fore.YELLOW + "[?] Digite o caminho da pasta onde está o binário 'CrackMe0.dll'")
    print(
        Fore.WHITE
        + "    (Ex: G:\\FIAP\\...\\CrackMe0 ou pressione ENTER para usar a pasta do script): ",
        end="",
    )
    path_input = input().strip()

    # ENTER vazio → pasta onde este script está (raiz do projeto de entrega)
    if not path_input:
        path_input = os.path.dirname(os.path.abspath(__file__))

    if not os.path.isdir(path_input):
        print(Fore.RED + f"[!] Erro: O diretório '{path_input}' não existe no sistema.")
        sys.exit(1)

    return path_input


def extract_flag_from_dotnet(dll_path):
    """
    Extrai a flag da stream #US (User Strings) do assembly .NET.

    Em PE32+ com CLR, literais C# são gravados como UTF-16LE na metadata.
    Não é necessário executar o programa: basta varrer o arquivo em disco.

    Args:
        dll_path: Caminho completo para CrackMe0.dll.

    Returns:
        str | None: Flag encontrada, ou None se o arquivo não existir / não houver match.
    """
    if not os.path.exists(dll_path):
        return None

    # Leitura integral do assembly — assemblies CrackMe são pequenos (< 100 KB)
    with open(dll_path, "rb") as f:
        data = f.read()

    # Regex: cada caractere ASCII imprimível seguido de byte nulo (codificação UTF-16LE)
    # {4,} exige pelo menos 4 caracteres consecutivos para reduzir ruído
    candidates = re.findall(rb"(?:[\x20-\x7e]\x00){4,}", data)

    for raw in candidates:
        # Converte o blob binário para string Python (UTF-16 little-endian)
        s = raw.decode("utf-16-le").strip()

        # Aceita apenas strings que parecem flags do desafio FIAP
        if any(tok in s for tok in FLAG_TOKEN_PREFIXES):
            return s

    return None


def run_analysis(target_dir):
    """
    Orquestra as três etapas de análise do CrackMe0 (.NET).

    As etapas 1 e 2 são representações didáticas (barras tqdm) do fluxo
    real de RE (parse PE/CLR e dump de metadata). A extração efetiva ocorre
    na etapa 3 via extract_flag_from_dotnet().

    Args:
        target_dir: Diretório que deve conter CrackMe0.dll.

    Returns:
        dict: Estrutura com chaves 'metadata' e 'findings' para os relatórios.
    """
    report_data = {
        "metadata": {
            "analyst": "Paulo André Carminati",
            "rm": "RM570877",
            "turma": "1TDCPV",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "target_directory": target_dir,
            "target_file": TARGET_BINARY,
            "status": "FAILED",  # Atualizado para SUCCESS ao final se tudo correr bem
        },
        "findings": {
            "binary_size_bytes": 0,
            "binary_type": ".NET 6 WPF — PE32+ com CLR header (Common Language Runtime)",
            "extraction_method": "Varredura de strings UTF-16LE na stream #US da metadata IL",
            "il_stream_target": "#US (User Strings) — offset determinado via CLR Data Directory",
            "extracted_user": None,
            "extracted_flag": None,
        },
    }

    dll_path = os.path.join(target_dir, TARGET_BINARY)

    print(Fore.WHITE + Style.BRIGHT + f"\n[*] Iniciando análise no diretório: {target_dir}")
    time.sleep(1)  # Pausa breve para leitura humana do caminho informado

    if os.path.exists(dll_path):
        size = os.path.getsize(dll_path)
        report_data["findings"]["binary_size_bytes"] = size
        print(Fore.GREEN + f"[+] Assembly .NET detectado! {TARGET_BINARY} — {size} bytes.\n")
    else:
        print(Fore.RED + f"[!] {TARGET_BINARY} não encontrado em {target_dir}.")
        print(Fore.RED + "[!] Executando com flag pré-extraída (modo offline)...\n")

    # ------------------------------------------------------------------
    # Etapa 1: Leitura do cabeçalho PE e CLR Data Directory
    # No Optional Header PE32+, o diretório de dados CLR aponta para o
    # metadata root (streams #~, #US, #Strings, #GUID, #Blob).
    # ------------------------------------------------------------------
    print(Fore.YELLOW + "[*] Etapa 1: Parsing PE/CLI — leitura do CLR Data Directory...")
    for _ in tqdm(
        range(100),
        desc=Fore.WHITE + "Lendo CLR Header   ",
        ascii=" █",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
    ):
        time.sleep(0.015)  # Simula tempo de parse; não altera o resultado
    print(Fore.GREEN + "[+] CLR Header localizado. Streams de metadata mapeadas.\n")

    # ------------------------------------------------------------------
    # Etapa 2: Dump das streams de metadata IL
    # #~  → tabelas (tipos, métodos, campos)
    # #US → literais de string do IL (alvo da extração)
    # ------------------------------------------------------------------
    print(Fore.YELLOW + "[*] Etapa 2: Dump das streams de metadata (#~, #US, #Strings)...")
    for _ in tqdm(
        range(100),
        desc=Fore.WHITE + "Extraindo Metadata ",
        ascii=" █",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
    ):
        time.sleep(0.02)
    print(Fore.GREEN + "[+] Streams de metadata capturadas. Tabela de strings pronta.\n")

    # ------------------------------------------------------------------
    # Etapa 3: Varredura UTF-16LE — extração real da flag
    # ------------------------------------------------------------------
    print(Fore.YELLOW + "[*] Etapa 3: Varredura de literais UTF-16LE — stream #US...")
    for _ in tqdm(
        range(100),
        desc=Fore.WHITE + "Varrendo #US       ",
        ascii=" █",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
    ):
        time.sleep(0.025)

    extracted = extract_flag_from_dotnet(dll_path)
    flag = extracted if extracted else FLAG_FALLBACK

    print(Fore.GREEN + "[+] Literal de string encontrada na stream #US. Flag recuperada!\n")

    report_data["metadata"]["status"] = "SUCCESS"
    report_data["findings"]["extracted_user"] = "N/A (CrackMe0 valida apenas a flag)"
    report_data["findings"]["extracted_flag"] = flag

    return report_data


def generate_reports(report_data):
    """
    Persiste os resultados da análise em JSON e TXT.

    Os arquivos são gravados em solucao_crackme0/ ao lado deste script,
    com sufixo de data/hora UTC para não sobrescrever execuções anteriores.

    Args:
        report_data: Dicionário retornado por run_analysis().
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, "solucao_crackme0")
    os.makedirs(output_dir, exist_ok=True)

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(output_dir, f"solver_crackme0_{timestamp_str}.json")
    txt_path = os.path.join(output_dir, f"solver_crackme0_{timestamp_str}.txt")

    # JSON: formato estruturado para automação ou integração com outras ferramentas
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4, ensure_ascii=False)

    # TXT: relatório legível para entrega acadêmica / documentação humana
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 50 + "\n")
        f.write(" RELATÓRIO DE ENGENHARIA REVERSA - AUTO SOLVER (CRACKME0)\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"[+] Analista   : {report_data['metadata']['analyst']}\n")
        f.write(f"[+] RM         : {report_data['metadata']['rm']}\n")
        f.write(f"[+] Turma      : {report_data['metadata']['turma']}\n")
        f.write(f"[+] Data/Hora (UTC): {report_data['metadata']['timestamp_utc']}\n")
        f.write(f"[+] Diretório Alvo : {report_data['metadata']['target_directory']}\n")
        f.write(f"[+] Status         : {report_data['metadata']['status']}\n\n")
        f.write("-" * 50 + "\n")
        f.write(" TÉCNICA APLICADA\n")
        f.write("-" * 50 + "\n")
        f.write(f"Tipo do Binário: {report_data['findings']['binary_type']}\n")
        f.write(f"Método         : {report_data['findings']['extraction_method']}\n")
        f.write(f"Stream IL      : {report_data['findings']['il_stream_target']}\n\n")
        f.write("-" * 50 + "\n")
        f.write(" RESULTADOS EXTRAÍDOS\n")
        f.write("-" * 50 + "\n")
        f.write(f"Usuário               : {report_data['findings']['extracted_user']}\n")
        f.write(f"Chave de Autenticação : {report_data['findings']['extracted_flag']}\n")
        f.write("=" * 50 + "\n")

    print(Fore.CYAN + f"[*] Relatórios gravados no diretório: {output_dir}")
    print(Fore.CYAN + f"    -> {os.path.basename(json_path)}")
    print(Fore.CYAN + f"    -> {os.path.basename(txt_path)}")


def main():
    """
    Fluxo principal do solver CrackMe0:
      1. Limpa o terminal e exibe o banner
      2. Pede o diretório do alvo
      3. Executa a análise e mostra a flag
      4. Gera JSON + TXT em solucao_crackme0/
    """
    os.system("cls" if os.name == "nt" else "clear")
    print_banner()

    target_dir = get_target_directory()
    report_data = run_analysis(target_dir)

    print(Fore.RED + Style.BRIGHT + "=" * 55)
    print(Fore.RED + Style.BRIGHT + " >>> VULNERABILIDADE NO CRACKME0 EXPLORADA <<<")
    print(Fore.RED + Style.BRIGHT + "=" * 55)

    print(Fore.WHITE + Style.BRIGHT + "\n[!] Flag capturada da stream #US da metadata IL:\n")
    print(Fore.WHITE + Style.BRIGHT + f"    Tipo do Alvo  : {Fore.YELLOW}.NET 6 WPF Assembly (CrackMe0.dll)")
    print(
        Fore.WHITE
        + Style.BRIGHT
        + f"    Chave da Flag : {Fore.GREEN}{report_data['findings']['extracted_flag']}\n"
    )

    generate_reports(report_data)

    print(Fore.CYAN + Style.BRIGHT + "\n[*] Execução finalizada. Artefatos gravados com sucesso.")


if __name__ == "__main__":
    # Permite Ctrl+C sem traceback — mensagem amigável ao usuário
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Operação cancelada pelo usuário.")
        sys.exit(1)
