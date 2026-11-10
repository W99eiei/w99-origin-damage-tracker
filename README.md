# W99 Origin Damage Tracker

Fonte da versão 1.0 do medidor de combate comunitário para Windows. O aplicativo lê passivamente eventos de rede do jogo com Npcap e apresenta dano, cura e relatórios locais. Não usa OCR nem leitura de memória do processo.

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

Ao abrir, o aplicativo consulta a API pública de releases do GitHub para verificar se há uma versão estável mais recente. Essa consulta envia apenas uma requisição normal ao GitHub com a versão do aplicativo; não envia capturas, nomes, UIDs nem estatísticas. Se não houver conexão, a captura funciona normalmente e o aviso de atualização é omitido. O botão de atualização abre a página de releases para que cada pessoa confira as notas e baixe o arquivo manualmente.

No aplicativo, a captura continua ativa sem limite de duração até ser parada manualmente ou o programa ser encerrado. A opção de linha de comando `--seconds` ainda aceita duração limitada para capturas de diagnóstico; `--seconds 0` ativa o modo sem limite.

## Gerar o executável

Com as dependências instaladas, execute `./build_windows.ps1` no PowerShell. O executável será criado em `dist/`. Npcap não é empacotado: cada usuário deve obtê-lo e aceitar sua licença diretamente com o fornecedor.

## Publicar uma atualização

Publique cada nova versão estável como um GitHub Release neste repositório, com uma tag semântica superior à versão anterior (por exemplo `v1.0.1` ou `v1.1.0`) e anexe o ZIP distribuível. O aplicativo consulta o release estável mais recente e oferece um botão para abrir sua página. Rascunhos e pré-lançamentos não geram aviso.

## Dados e arquivos excluídos

Este repositório não contém capturas PCAP/ETL, sessões de jogo, UIDs/nicks locais, relatórios, executáveis do jogo, dumps de memória, ferramentas de inspeção de memória ou dependências binárias vendorizadas. Os retratos de personagens de terceiros e o ícone do aplicativo foram omitidos; a interface usa iniciais quando as imagens não estão disponíveis e o executável usa o ícone padrão do PyInstaller.

`analise_engine/protocol_table.bin` e `protocolos_ids.json` são os dados mínimos necessários para decodificar os eventos suportados pela versão de protocolo analisada. Uma atualização do jogo pode alterar o protocolo e exigir nova validação.

A captura ao vivo descobre automaticamente conexões TCP estabelecidas pelo processo do jogo, ignora as portas web comuns 80/443 e atualiza o filtro Npcap quando os fluxos mudam. O parser ainda precisa ser validado após atualizações do jogo.

## Aviso de uso

Este é um projeto independente e não aprovado pela Netmarble. O uso de software de terceiros e captura de tráfego pode estar sujeito às regras do jogo e ser sinalizado pelo anticheat. Os termos não avaliam especificamente este aplicativo; não há garantia contra alertas, restrições ou banimento. Leia os termos vigentes antes de usar: <https://help.netmarble.com/en/terms/terms_of_service_pc_en>.

## Licença

Nenhuma licença de código aberto foi escolhida para este repositório. Até que uma licença seja adicionada, todos os direitos permanecem reservados.

