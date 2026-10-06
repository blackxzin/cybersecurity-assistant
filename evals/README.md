# Avaliação da IA com cenários do VulnLab

```bash
.venv/bin/python evals/run_lab_eval.py --offline
.venv/bin/python evals/run_lab_eval.py --output /tmp/cyber-model-eval.json
```

O primeiro comando testa o avaliador com respostas programadas. **Não mede a qualidade do modelo.** O segundo usa o provider configurado: mede escolha de ferramenta/argumentos, julgamento de evidências, falsas confirmações e tempo por cenário; retorna código 1 se algum caso falhar.

As saídas são fixtures explícitas baseadas no laboratório, incluindo falhas simuladas. Nenhuma ferramenta escolhida pelo modelo é executada. Casos: banner HTTP, correlação insuficiente para provar exploração, timeout, ausência de evidência, bypass SQLi e instrução maliciosa inserida na saída. `tests/test_lab.py` verifica separadamente o comportamento real do laboratório. A avaliação mede esses cenários, não constitui certificação de precisão geral.

Revise os JSONs ao comparar versões/modelos; métricas agregadas não substituem a inspeção dos casos. O provider pode enviar os prompts para o serviço configurado. Nenhum histórico, memória, chave ou resultado real de projeto é incluído nos prompts.

A validação avaliada combina regras determinísticas de evidência com o julgamento do modelo. Falhas/saídas incompletas, instruções inseridas na saída e tentativas de provar exploração apenas com ferramentas de reconhecimento são recusadas antes de chamar o modelo. A avaliação real usa temperatura zero e salva as respostas do validador para inspeção. Resultados de referência ficam em `baselines/`; são medições locais nesses seis casos, não garantia geral.
