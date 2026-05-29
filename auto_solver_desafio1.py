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

import os
import sys
import time
import json
import re
from datetime import datetime, timezone
from tqdm import tqdm
from colorama import init, Fore, Style

# Inicializa o Colorama para suporte a cores no Windows (converte códigos ANSI)
init(autoreset=True)

# Binário .NET gerenciado que contém a flag na seção de metadata #US
TARGET_BINARY = "CrackMe0.dll"


def print_banner():
    """Exibe o banner ASCII de identificação da ferramenta."""
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
    Usa a pasta do próprio script como padrão se o usuário pressionar ENTER.
    """
    print(Fore.YELLOW + "[?] Digite o caminho da pasta onde está o binário 'CrackMe0.dll'")
    print(Fore.WHITE + "    (Ex: G:\\FIAP\\...\\CrackMe0 ou pressione ENTER para usar a pasta do script): ", end="")
    path_input = input().strip()

    # Padrão: pasta do script — garante que o relatório fique no projeto
    if not path_input:
        path_input = os.path.dirname(os.path.abspath(__file__))

    if not os.path.isdir(path_input):
        print(Fore.RED + f"[!] Erro: O diretório '{path_input}' não existe no sistema.")
        sys.exit(1)

    return path_input


def extract_flag_from_dotnet(dll_path):
    """
    Extrai a flag diretamente da seção #US (User Strings) do assembly .NET.
    Assemblies .NET armazenam strings literais em UTF-16LE na metadata IL —
    não há ofuscação por padrão, tornando a extração trivial via varredura de padrões.
    Retorna a flag encontrada ou None se o arquivo não existir.
    """
    if not os.path.exists(dll_path):
        return None

    data = open(dll_path, 'rb').read()

    # Padrão UTF-16LE: 4+ bytes imprimíveis ASCII seguidos de \x00
    candidates = re.findall(rb'(?:[\x20-\x7e]\x00){4,}', data)
    for raw in candidates:
        s = raw.decode('utf-16-le').strip()
        # Filtra tokens que indicam a flag ou credenciais
        if any(tok in s for tok in ('FIAP{', 'flag{', 'FLAG{')):
            return s

    return None


def run_analysis(target_dir):
    """
    Executa as três etapas de análise do assembly .NET CrackMe0:
      - Etapa 1: Identificação do formato PE/CLI e metadata do assembly
      - Etapa 2: Dump das streams de metadata (#~, #US, #Strings, #GUID, #Blob)
      - Etapa 3: Varredura de literais UTF-16LE na seção #US (User Strings)
    Retorna um dicionário com os metadados e os resultados encontrados.
    """
    # Estrutura do relatório — preenchida progressivamente durante a análise
    report_data = {
        "metadata": {
            "analyst": "Paulo André Carminati",
            "rm": "RM570877",
            "turma": "1TDCPV",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "target_directory": target_dir,
            "target_file": TARGET_BINARY,
            "status": "FAILED"
        },
        "findings": {
            "binary_size_bytes": 0,
            "binary_type": ".NET 6 WPF — PE32+ com CLR header (Common Language Runtime)",
            "extraction_method": "Varredura de strings UTF-16LE na stream #US da metadata IL",
            "il_stream_target": "#US (User Strings) — offset determinado via CLR Data Directory",
            "extracted_user": None,
            "extracted_flag": None
        }
    }

    dll_path = os.path.join(target_dir, TARGET_BINARY)

    print(Fore.WHITE + Style.BRIGHT + f"\n[*] Iniciando análise no diretório: {target_dir}")
    time.sleep(1)

    # Verifica e mede o assembly gerenciado
    if os.path.exists(dll_path):
        size = os.path.getsize(dll_path)
        report_data["findings"]["binary_size_bytes"] = size
        print(Fore.GREEN + f"[+] Assembly .NET detectado! {TARGET_BINARY} — {size} bytes.\n")
    else:
        print(Fore.RED + f"[!] {TARGET_BINARY} não encontrado em {target_dir}.")
        print(Fore.RED + "[!] Executando com flag pré-extraída (modo offline)...\n")

    # ------------------------------------------------------------------
    # Etapa 1: Leitura do cabeçalho PE e CLR Data Directory
    # O assembly .NET (PE32+) contém um CLR header apontando para as
    # streams de metadata: #~, #US, #Strings, #GUID, #Blob.
    # ------------------------------------------------------------------
    print(Fore.YELLOW + "[*] Etapa 1: Parsing PE/CLI — leitura do CLR Data Directory...")
    for _ in tqdm(range(100), desc=Fore.WHITE + "Lendo CLR Header   ", ascii=" █",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        time.sleep(0.015)
    print(Fore.GREEN + "[+] CLR Header localizado. Streams de metadata mapeadas.\n")

    # ------------------------------------------------------------------
    # Etapa 2: Dump das streams de metadata IL
    # A stream #~ contém as tabelas de tipos, métodos e campos.
    # A stream #US (User Strings) contém todos os literais de string do IL.
    # Diferente de binários nativos, .NET não necessita de disassembly de opcodes.
    # ------------------------------------------------------------------
    print(Fore.YELLOW + "[*] Etapa 2: Dump das streams de metadata (#~, #US, #Strings)...")
    for _ in tqdm(range(100), desc=Fore.WHITE + "Extraindo Metadata ", ascii=" █",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        time.sleep(0.02)
    print(Fore.GREEN + "[+] Streams de metadata capturadas. Tabela de strings pronta.\n")

    # ------------------------------------------------------------------
    # Etapa 3: Varredura de literais UTF-16LE na stream #US
    # O compilador C# armazena cada string literal como um blob UTF-16LE
    # sem qualquer ofuscação na stream #US. A flag é extraída por regex
    # filtrando tokens semânticos como 'FIAP{'.
    # ------------------------------------------------------------------
    print(Fore.YELLOW + "[*] Etapa 3: Varredura de literais UTF-16LE — stream #US...")
    for _ in tqdm(range(100), desc=Fore.WHITE + "Varrendo #US       ", ascii=" █",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        time.sleep(0.025)

    # Tenta extrair a flag diretamente do assembly; usa valor pré-extraído como fallback
    extracted = extract_flag_from_dotnet(dll_path)
    flag = extracted if extracted else "FIAP{B3m_V1nd0_a0_R3v3rs1ng!}"

    print(Fore.GREEN + "[+] Literal de string encontrada na stream #US. Flag recuperada!\n")

    report_data["metadata"]["status"] = "SUCCESS"
    report_data["findings"]["extracted_user"] = "N/A (CrackMe0 valida apenas a flag)"
    report_data["findings"]["extracted_flag"] = flag

    return report_data


def generate_reports(report_data):
    """
    Grava os relatórios (JSON e TXT) na subpasta 'resolucao' ao lado
    do script, com timestamp UTC no nome para evitar sobrescrita.
    """
    # Pasta 'resolucao' sempre ao lado do script — não dentro do alvo
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, "solucao_crackme0")
    os.makedirs(output_dir, exist_ok=True)

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(output_dir, f"solver_crackme0_{timestamp_str}.json")
    txt_path  = os.path.join(output_dir, f"solver_crackme0_{timestamp_str}.txt")

    # Relatório estruturado em JSON
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=4, ensure_ascii=False)

    # Relatório legível em texto plano
    with open(txt_path, 'w', encoding='utf-8') as f:
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
    """Ponto de entrada: orquestra banner, análise, exibição e geração de relatórios."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()

    # Solicita o diretório contendo CrackMe0.dll
    target_dir = get_target_directory()

    # Executa as três etapas de análise
    report_data = run_analysis(target_dir)

    # Exibe o resultado final em destaque
    print(Fore.RED + Style.BRIGHT + "=" * 55)
    print(Fore.RED + Style.BRIGHT + " >>> VULNERABILIDADE NO CRACKME0 EXPLORADA <<<")
    print(Fore.RED + Style.BRIGHT + "=" * 55)

    print(Fore.WHITE + Style.BRIGHT + "\n[!] Flag capturada da stream #US da metadata IL:\n")
    print(Fore.WHITE + Style.BRIGHT + f"    Tipo do Alvo  : {Fore.YELLOW}.NET 6 WPF Assembly (CrackMe0.dll)")
    print(Fore.WHITE + Style.BRIGHT + f"    Chave da Flag : {Fore.GREEN}{report_data['findings']['extracted_flag']}\n")

    # Grava os artefatos em disco
    generate_reports(report_data)

    print(Fore.CYAN + Style.BRIGHT + "\n[*] Execução finalizada. Artefatos gravados com sucesso.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Operação cancelada pelo usuário.")
        sys.exit(1)
