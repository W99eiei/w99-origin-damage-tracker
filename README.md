# W99 Origin Damage Tracker

Fonte do medidor de combate comunitário para Windows. O aplicativo lê passivamente eventos de rede do jogo com Npcap e apresenta dano, cura e relatórios locais. Não usa OCR nem leitura de memória do processo.

## Requisitos

- Windows 10/11, 64 bits
- Python 3.11 ou superior
- Npcap instalado separadamente a partir do site oficial
- Microsoft Edge WebView2 Runtime

## Executar a partir do código

1. Instale Npcap e WebView2 pelos respectivos canais oficiais.
2. Crie um ambiente virtual e instale as dependências de compilação listadas em `requirements-build.txt`.
3. Abra o PowerShell como administrador e execute `python dps_meter_exe.py`.

O primeiro início solicita privilégios de administrador para a captura Npcap. O painel local usa `127.0.0.1`. Os relatórios e preferências permanecem em arquivos locais.

No aplicativo, a captura continua ativa sem limite de duração até ser parada manualmente ou o programa ser encerrado. A opção de linha de comando `--seconds` ainda aceita duração limitada para capturas de diagnóstico; `--seconds 0` ativa o modo sem limite.

## Gerar o executável

Com as dependências instaladas, execute `./build_windows.ps1` no PowerShell. O executável será criado em `dist/`. Npcap não é empacotado: cada usuário deve obtê-lo e aceitar sua licença diretamente com o fornecedor.

## Dados e arquivos excluídos

Este repositório não contém capturas PCAP/ETL, sessões de jogo, UIDs/nicks locais, relatórios, executáveis do jogo, dumps de memória, ferramentas de inspeção de memória ou dependências binárias vendorizadas. Os retratos de personagens de terceiros também foram omitidos; a interface usa iniciais quando essas imagens não estão disponíveis.

`analise_engine/protocol_table.bin` e `protocolos_ids.json` são os dados mínimos necessários para decodificar os eventos suportados pela versão de protocolo analisada. Uma atualização do jogo pode alterar o protocolo e exigir nova validação.

## Aviso de uso

Este é um projeto independente e não aprovado pela Netmarble. O uso de software de terceiros e captura de tráfego pode estar sujeito às regras do jogo e ser sinalizado pelo anticheat. Os termos não avaliam especificamente este aplicativo; não há garantia contra alertas, restrições ou banimento. Leia os termos vigentes antes de usar: <https://help.netmarble.com/en/terms/terms_of_service_pc_en>.

O resultado é estimado a partir dos eventos observados e pode ficar incompleto ou atribuir dano de forma imprecisa. Os relatórios podem conter dados dos integrantes do grupo; revise-os antes de compartilhar.

## Licença

Nenhuma licença de código aberto foi escolhida para este repositório. Até que uma licença seja adicionada, todos os direitos permanecem reservados.

