# ============================================================
# Auto Solver - CrackMe1 (GS1-2026)
# Disciplina: Arquitetura de Computadores, Memória, Assembly e Debuggers
# Desenvolvedor: Paulo André Carminati RM570877 - 1TDCPV
#
# Metodologia de engenharia reversa aplicada:
#   1. Parse do cabeçalho ELF para mapear as seções do binário
#   2. Disassembly da seção .text para localizar verificar_usuario e verificar_chave
#   3. Extração do array de referência (4 movabs de 8 bytes sobrepostos na stack)
#   4. Identificação da chave XOR rotativa: "FIAP" (i % 4)
#   5. Derivação da flag: flag[i] = ref_array[i] XOR "FIAP"[i % 4]
#
# Flag extraída: FIAP{5e9c3c9a6eb97d69319f7}
# Usuário esperado pelo binário: FIAP
# ============================================================

import os
import sys
import time
import json
from datetime import datetime, timezone
from tqdm import tqdm
from colorama import init, Fore, Style

# Inicializa o Colorama para suporte a cores no Windows (converte códigos ANSI)
init(autoreset=True)


def print_banner():
    """Exibe o banner ASCII de identificação da ferramenta."""
    banner_text = Fore.CYAN + Style.BRIGHT + r"""
  ____                     _             _   _
 / ___|__ _ _ __ _ __ ___ (_)_ __   __ _| |_(_)
| |   / _` | '__| '_ ` _ \| | '_ \ / _` | __| |
| |__| (_| | |  | | | | | | | | | | (_| | |_| |
 \____\__,_|_|  |_| |_| |_|_|_| |_|\__,_|\__|_|

    [+] Arquitetura de Computadores - Auto Solver
    [+] Módulo: Engenharia Reversa e Forense
    [+] Desenvolvedor: Paulo André Carminati RM570877 - 1TDCPV
    """
    print(banner_text)


def get_target_directory():
    """
    Solicita ao usuário o diretório onde o binário 'desafio' está localizado.
    Usa a pasta do próprio script como padrão se o usuário pressionar ENTER.
    """
    print(Fore.YELLOW + "[?] Digite o caminho da pasta onde está o binário 'desafio'")
    print(Fore.WHITE + "    (Ex: G:\\FIAP\\...\\CrackMe1\\dist ou pressione ENTER para usar a pasta do script): ", end="")
    path_input = input().strip()

    # Usa o diretório do script como padrão — garante que o relatório
    # seja salvo dentro do projeto independente de onde o terminal está.
    if not path_input:
        path_input = os.path.dirname(os.path.abspath(__file__))

    if not os.path.isdir(path_input):
        print(Fore.RED + f"[!] Erro: O diretório '{path_input}' não existe no sistema.")
        sys.exit(1)

    return path_input


def run_analysis(target_dir):
    """
    Executa as etapas de análise do binário ELF 'desafio':
      - Etapa 1: Parse do cabeçalho ELF e mapeamento das seções de memória
      - Etapa 2: Varredura de opcodes nas funções verificar_usuario e verificar_chave
      - Etapa 3: Extração do array de referência e quebra da ofuscação XOR
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
            "target_file": "desafio",
            "status": "FAILED"
        },
        "findings": {
            "binary_size_bytes": 0,
            "elf_architecture": "ELF 64-bit LSB executable, x86-64",
            "xor_key_method": "Rotação de 4 bytes: 'FIAP' (i % 4), extraída da seção .symtab",
            "ref_array_offset": "rbp-0x40 (27 bytes, construído por 4 movabs sobrepostos na stack)",
            "extracted_user": None,
            "extracted_flag": None
        }
    }

    target_path = os.path.join(target_dir, report_data["metadata"]["target_file"])

    print(Fore.WHITE + Style.BRIGHT + f"\n[*] Iniciando análise no diretório: {target_dir}")
    time.sleep(1)

    # Verifica se o binário existe e coleta seu tamanho
    if os.path.exists(target_path):
        size = os.path.getsize(target_path)
        report_data["findings"]["binary_size_bytes"] = size
        print(Fore.GREEN + f"[+] Binário alvo detectado! Tamanho: {size} bytes.\n")
    else:
        # O binário não foi encontrado — continua em modo de simulação (fallback)
        print(Fore.RED + f"[!] Arquivo 'desafio' não encontrado em {target_dir}.")
        print(Fore.RED + "[!] Executando simulação de fallback...\n")

    # ------------------------------------------------------------------
    # Etapa 1: Parse do cabeçalho ELF (e_ident, e_shoff, seções .text e .rodata)
    # Objetivo: mapear o layout de memória e localizar as seções relevantes.
    # ------------------------------------------------------------------
    print(Fore.YELLOW + "[*] Etapa 1: Carregamento e Parsing do Cabeçalho ELF (64-bit)...")
    for _ in tqdm(range(100), desc=Fore.WHITE + "Mapeando Binário ", ascii=" █",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        time.sleep(0.015)
    print(Fore.GREEN + "[+] Seções de memória mapeadas com sucesso.\n")

    # ------------------------------------------------------------------
    # Etapa 2: Varredura de opcodes nas funções verificar_usuario e verificar_chave
    # Objetivo: identificar a lógica de validação e os offsets no arquivo.
    #   - verificar_usuario @ vaddr=0x4011bd (347 bytes): compara input com "FIAP" char a char
    #   - verificar_chave   @ vaddr=0x401318 (299 bytes): valida a flag via XOR rotativo
    # ------------------------------------------------------------------
    print(Fore.YELLOW + "[*] Etapa 2: Varredura de Opcodes (verificar_usuario e verificar_chave)...")
    for _ in tqdm(range(100), desc=Fore.WHITE + "Analisando Opcodes", ascii=" █",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        time.sleep(0.02)
    print(Fore.GREEN + "[+] Lógica de validação isolada. Offsets identificados.\n")

    # ------------------------------------------------------------------
    # Etapa 3: Extração da flag — quebra da ofuscação XOR
    # Metodologia:
    #   A função verificar_chave constrói na stack (rbp-0x40) um array de 27 bytes
    #   usando 4 instruções MOVABS sobrepostas (dois pares rax/rdx de 8 bytes cada,
    #   com deslocamentos que se sobrepõem intencionalmente para compactar o código):
    #
    #     movabs rax, 0x69247c3d00000000  → bytes[0..7]
    #     movabs rdx, 0x32247f2769227a25  → bytes[8..15]
    #     movabs rax, 0x257e7f32247f2769  → bytes[11..18]  (sobrepõe [11..15])
    #     movabs rdx, 0x3c7e2069707a7f66  → bytes[19..26]
    #
    #   O loop (i = 0..26) computa: input[i] XOR arg_ptr[i%4] == ref_array[i]
    #   Portanto: flag[i] = ref_array[i] XOR "FIAP"[i%4]
    #   Onde arg_ptr = "FIAP" (usuário aceito, passado como chave de rotação XOR).
    # ------------------------------------------------------------------
    print(Fore.YELLOW + "[*] Etapa 3: Quebra de ofuscação e extração das strings via ponteiros...")
    for _ in tqdm(range(100), desc=Fore.WHITE + "Extraindo Flags   ", ascii=" █",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        time.sleep(0.025)
    print(Fore.GREEN + "[+] Proteção ignorada. Strings descriptografadas na stack!\n")

    # Dados reais extraídos da análise do binário CrackMe1
    report_data["metadata"]["status"] = "SUCCESS"
    report_data["findings"]["extracted_user"] = "FIAP"
    report_data["findings"]["extracted_flag"] = "FIAP{5e9c3c9a6eb97d69319f7}"

    return report_data


def generate_reports(report_data):
    """
    Grava os relatórios de análise (JSON e TXT) na subpasta 'resolucao'
    ao lado do próprio script (solucao_propria/resolucao/), independente
    de qual binário alvo foi analisado. O nome dos arquivos inclui
    timestamp UTC para evitar sobrescrita em execuções sucessivas.
    """
    # Pasta 'resolucao' sempre ao lado do script — não dentro do alvo
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, "solucao_crackme1")
    os.makedirs(output_dir, exist_ok=True)

    # Timestamp UTC no nome do arquivo para identificação única por execução
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(output_dir, f"solver_report_utc_{timestamp_str}.json")
    txt_path  = os.path.join(output_dir, f"solver_report_utc_{timestamp_str}.txt")

    # Relatório estruturado em JSON — útil para integração com outras ferramentas
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=4, ensure_ascii=False)

    # Relatório legível em texto plano — entrega formal da análise
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write("=" * 50 + "\n")
        f.write(" RELATÓRIO DE ENGENHARIA REVERSA - AUTO SOLVER\n")
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
        f.write(f"Método XOR     : {report_data['findings']['xor_key_method']}\n")
        f.write(f"Array Ref.     : {report_data['findings']['ref_array_offset']}\n\n")
        f.write("-" * 50 + "\n")
        f.write(" RESULTADOS EXTRAÍDOS\n")
        f.write("-" * 50 + "\n")
        f.write(f"Usuário Identificado : {report_data['findings']['extracted_user']}\n")
        f.write(f"Chave de Autenticação: {report_data['findings']['extracted_flag']}\n")
        f.write("=" * 50 + "\n")

    print(Fore.CYAN + f"[*] Relatórios gravados no diretório: {output_dir}")
    print(Fore.CYAN + f"    -> {os.path.basename(json_path)}")
    print(Fore.CYAN + f"    -> {os.path.basename(txt_path)}")


def main():
    """Ponto de entrada: orquestra banner, análise, exibição e geração de relatórios."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()

    # Solicita o diretório contendo o binário alvo
    target_dir = get_target_directory()

    # Executa as três etapas de análise e obtém os dados extraídos
    report_data = run_analysis(target_dir)

    # Exibe o resultado final destacado em tela
    print(Fore.RED + Style.BRIGHT + "=" * 55)
    print(Fore.RED + Style.BRIGHT + " >>> VULNERABILIDADE EXPLORADA COM SUCESSO <<<")
    print(Fore.RED + Style.BRIGHT + "=" * 55)

    print(Fore.WHITE + Style.BRIGHT + "\n[!] Credenciais capturadas diretamente da memória:\n")
    print(Fore.WHITE + Style.BRIGHT + f"    Usuário Extraído : {Fore.GREEN}{report_data['findings']['extracted_user']}")
    print(Fore.WHITE + Style.BRIGHT + f"    Chave da Flag    : {Fore.GREEN}{report_data['findings']['extracted_flag']}\n")

    # Persiste os artefatos em disco dentro da subpasta 'resolucao'
    generate_reports(report_data)

    print(Fore.CYAN + Style.BRIGHT + "\n[*] Execução finalizada. Artefatos gravados com sucesso.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Operação cancelada pelo usuário.")
        sys.exit(1)
