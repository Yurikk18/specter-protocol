# Projeto Specter: Proof-Carrying Tokens — Ecash Pós-Quântico com Compliance Privada

## Visão

Um novo **primitivo criptográfico** — o Proof-Carrying Token (PCT) — que transforma dinheiro digital num objeto auto-verificável que prova simultaneamente a sua validade, a compliance do portador e a integridade de todo o seu histórico, sem revelar nada sobre quem o possui.

Specter não é "mais um ecash com features extras." É uma **categoria nova**: bearer tokens que carregam as suas próprias provas, construídos sobre criptografia pós-quântica desde o dia 1.

Propriedades simultâneas:
- **Descentralizado** — emissão por threshold de nós, sem autoridade central
- **Pós-quântico** — lattice-based desde a fundação, não como migração tardia
- **Privado** — sem anonymity budgets, sem rastreio, sem vigilância
- **Compliant** — cada token prova que o portador passou KYC e não está sancionado, SEM revelar identidade
- **Offline** — funciona sem internet com garantias económicas (não perfeito, mas estritamente melhor que qualquer concorrente)
- **Transferível** — tokens passam de mão em mão com tamanho constante (não cresce com transferências)
- **Open source** — protocolo + código, modelo Tor

Como bearer instrument, o protocolo é agnóstico a quem o usa — funciona para qualquer entidade que possua a chave, seja humano ou software autónomo, sem modificações ao protocolo.

---

## A Inovação Central: Proof-Carrying Tokens (PCT)

### O Problema Fundamental

Em todo sistema de ecash existente, um token é uma coisa e as provas da sua validade são outras separadas:

```
Sistema convencional:
  Token = blind_signature (20-36KB em lattices)
        + ZK_proof_de_validade (100-200KB)
        + credential_de_compliance (5-80KB)
        + commitment_de_valor (1KB)
        + histórico_de_transferências (cresce linearmente)
  Total: 200KB - 1MB, múltiplas verificações separadas
```

### A Solução

```
Proof-Carrying Token (PCT):
  Token = UM ÚNICO objeto criptográfico que prova simultaneamente:
    1. Foi emitido legitimamente (threshold de signatários)
    2. Não foi gasto (nullifier commitment)
    3. O portador é compliant (credential anónima embedded)
    4. O valor é válido (range proof)
    5. As N últimas transferências foram válidas (fold recursivo bounded)
  Total estimado: 300-600KB, UMA verificação
```

**O que torna isto possível**: LatticeFold+ (CRYPTO 2025, Dan Boneh & Binyi Chen) — o primeiro esquema de folding recursivo sobre lattices com performance comparável ao HyperNova. Permite comprimir provas cumulativas em tamanho constante (até um bound). Publicado em 2025 — ninguém aplicou a ecash ainda.

**Alternativa se LatticeFold+ for insuficiente**: Holography Accumulation (ePrint 2026/538, Março 2026) — um framework que NÃO é folding. Acumula verificações holográficas de polinómios e colapsa tudo numa única avaliação polinomial. Genuinamente diferente de Nova/LatticeFold.

### Tamanhos Reais (Honestidade Técnica)

Os benchmarks publicados indicam:
- LatticeFold+ para 2^20 constraints: ~17MB (sem otimizações)
- Com otimizações l2-norm: ~110-175KB por folding proof
- Lattice range proofs isolados: >90KB (vs <1KB para Bulletproofs clássicos)
- **LaZer Library** (IBM Research, CCS 2024, ePrint 2024/1846): 40-60KB para proofs de ring signatures e anonymous credentials — a ferramenta mais prática existente
- Greyhound (lattice polynomial commitment): ~50KB proofs

Para um PCT completo (blind sig + nullifier + credential + range + fold), a **estimativa honesta é 300-600KB**. Isto é 150-300x maior que uma transação Zcash (~2KB). Não serve para micropagamentos — serve para transferências de valor médio/alto onde privacidade e segurança PQ justificam o overhead.

### Recursão Bounded (Limite de Transferências por Fold)

Kothapalli (CMU PhD, 2024) demonstrou que a soundness de IVC está provada apenas para profundidade de recursão logarítmica. Em profundidade polinomial, as garantias degradam. Isto significa que PCTs **não podem circular indefinidamente** com tamanho constante.

**Solução**: bound na profundidade de recursão. Cada PCT permite até N transferências (ex: 20-50) antes de exigir **renovação** (re-fold desde zero na rede). Isto casa naturalmente com o mecanismo de wear-out offline: o hash chain e o bound de recursão convergem no mesmo ponto — após N transferências, o token DEVE ir online.

### Por Que Isto É Novo

- Ninguém aplicou LatticeFold+ a ecash
- Ninguém criou tokens que carregam compliance credentials dentro do fold
- Ninguém fez ecash com tamanho constante (bounded) por transferência via folding recursivo
- Ninguém combinou tudo isto com pós-quântico

É mais preciso chamar isto de **aplicação inédita de recursive proof composition a ecash** do que "primitivo novo" — a honestidade técnica é importante.

### Prior Art: Trabalho Relacionado

O grupo de Geoffrey Goodell (UCL) publicou trabalho que se sobrepõe parcialmente ao conceito PCT:

- **Self-Validating Tokens** (arXiv:2409.01958, Set 2024): tokens que carregam prova da própria validade via ZK, com burn-and-mint e reissuance. Aceite em FC 2025 Workshops.
- **Sark / USO Architecture** (arXiv:2512.20775, Dez 2025): "Unforgeable, Stateful, Oblivious" assets sem ledger global. Referência arquitectural mais próxima do PCT.
- **COME Protocol** (arXiv:2501.10419, Jan 2025): extensão para transferências compliant e oblivious.

**Diferenciação de Specter vs Sark/USO**:

| Aspecto | Sark/USO (Goodell) | Specter (PCT) |
|---|---|---|
| Pós-quântico | ❌ | ✅ (lattice-based nativo) |
| Tamanho constante | ❌ (cresce linearmente) | ✅ (fold recursivo bounded) |
| Compliance embedded no token | ❌ | ✅ (credential anónima dentro do fold) |
| Offline com garantias económicas | ❌ | ✅ (VDF + bonds + blame) |
| Descentralização | Parcial (crash-fault tolerant) | ✅ (BFT threshold) |

Goodell é prior art e aliado natural, não competidor. Deve ser citado explicitamente. Potencial para colaboração.

---

## O Gap Confirmado: O Que Não Existe

Após pesquisa exaustiva de papers, projetos e protótipos publicados até Abril 2026, confirmamos que **não existe nenhum sistema que combine**:

1. Emissão descentralizada (threshold blind signatures)
2. Resistência pós-quântica nativa (lattice-based)
3. Privacidade total sem anonymity budgets
4. Compliance verificável sem vigilância
5. Transferibilidade offline com garantias económicas
6. Tamanho constante por transferência (bounded)
7. Implementação funcional com código aberto

As peças individuais existem em papers separados. A combinação não existe.

### Tabela Comparativa (Corrigida e Expandida)

| Sistema | Descentralizado | PQ | Offline | Privacidade | Compliance Privada | Transferível | Tamanho Constante |
|---|---|---|---|---|---|---|---|
| Bitcoin | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | N/A |
| Monero | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | N/A |
| Zcash | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | N/A |
| Cashu | ❌ (mint) | ❌ | ❌ | ✅ | ❌ | ❌ | N/A |
| Fedimint | Parcial | ❌ | Parcial | ✅ | ❌ | ❌ | N/A |
| UTT | ✅ | ❌ | ❌ | ❌ (budgets) | ❌ | ✅ | N/A |
| Privacy Pools | ✅ | ❌ | ❌ | Parcial | Parcial (fundos) | N/A | N/A |
| Sark/USO | Parcial | ❌ | ❌ | ✅ | Parcial | ✅ | ❌ (linear) |
| **Specter** | **✅** | **✅** | **⚠️ Parcial** | **✅** | **✅** | **✅** | **✅ (bounded)** |

**Nota sobre Offline**: offline total sem TEE e sem double-spend é **matematicamente impossível** (formalizado no Offline CBDC Trilemma, TU Munich, Dezembro 2025, arXiv:2512.10636). O que Specter oferece é "offline com responsabilização e garantias económicas" — melhor que qualquer concorrente, mas não equivalente a cash físico.

---

## Arquitetura Técnica

### Camada 1: Emissão Descentralizada com Threshold Blind PCT

**Problema**: ecash clássico (Chaum) precisa de um mint centralizado que pode ser censurado, hackeado ou desligado.

**Solução**: threshold blind PCT issuance.

1. O utilizador prepara um commitment do valor + credential de identidade anónima
2. Cega tudo e envia a k-de-n nós signatários
3. Cada nó assina a sua parte sem ver o conteúdo (blind)
4. O utilizador combina as assinaturas parciais
5. Usa LatticeFold+ para **dobrar (fold)** a assinatura threshold + credential + range proof num **único PCT**

Resultado: um objeto de ~300-600KB que prova tudo numa verificação.

**Base criptográfica**:
- Lattice threshold blind signatures (Faller, Niot & Reichle, ePrint 2025/1566) — primeiro esquema do mundo, publicado em 2025. Overhead: 1.4-2.5x sobre non-threshold
- Improved lattice blind signatures (Jeudy & Sanders, CRYPTO 2025, ePrint 2024/1289) — 36KB/assinatura, com implementação GitHub
- Lattice blind signatures round-optimal (Agrawal et al., CCS 2023, ePrint 2023/077) — 20KB/assinatura
- LatticeFold+ recursive folding (Boneh & Chen, CRYPTO 2025, ePrint 2025/247) — 5-10x mais rápido que v1
- **LaZer Library** (Lyubashevsky, Seiler & Steuer, IBM Research, CCS 2024, ePrint 2024/1846) — biblioteca C production-quality para ZK proofs lattice-based, 40-60KB proofs. Gera proof systems automaticamente a partir de relações especificadas.
- Compact lattice threshold signatures (del Pino & Niot, PKC 2025, ePrint 2025/872) — threshold sig próximo do tamanho de um único Dilithium para T ≤ 8

**AVISO**: o esquema BLAZE (FC 2020) foi quebrado. Paper de criptanálise de Fevereiro 2026 confirma: "all previously known lattice-based blind signature schemes contain subtle flaws." Os papers acima (CCS 2023 e CRYPTO 2025) são o estado da arte correto.

**AVISO SOBRE COMPOSIÇÃO**: a composição de 5 primitivos lattice-based (blind signature + nullifier PRF + credential + range proof + folding) num único sistema NÃO tem análise de segurança unificada. Cada primitivo usa assumptions ligeiramente diferentes (MSIS, MLWE, variantes interativas). A "relaxed soundness" de provas lattice-based (witnesses extraídos num domínio mais largo que o do prover honesto) acumula slack em cada camada. Analisar formalmente esta composição é uma contribuição de pesquisa em si.

### Camada 2: Transferência com Fold-on-Transfer

**Problema**: no ecash clássico, transferir exige contactar o mint. No ecash transferível, cada transferência adiciona dados ao token (crescimento linear).

**Solução**: fold-on-transfer usando LatticeFold+ com **profundidade bounded**.

Quando Alice transfere para Bob:
1. Alice revela o PCT a Bob
2. Bob verifica localmente (uma verificação)
3. Alice cria uma prova de transferência
4. Bob **folda** a prova de transferência no PCT existente

**Tamanho constante bounded**: o PCT não cresce dentro do bound de N transferências (ex: 20-50). Após N transferências, o token deve ser renovado online (re-fold desde zero). Isto é análogo ao wear-out de hash chains, e os dois mecanismos convergem: o hash chain e o bound de recursão impõem o mesmo limite.

**Anti double-spend**: cada token tem um "desgaste" criptográfico (hash chain) — pode ser transferido N vezes offline antes de precisar ser renovado na rede. Quando vai online, se double-spend ocorreu, a rede detecta e identifica o fraudador (blame protocol) mas NÃO o receptor.

**Prior art direta**:
- Goodell, Toliver & Nakib (UCL, 2024) — self-validating tokens com burn-and-mint e ZK-verified reissuance. O conceito de token auto-verificável originou aqui; Specter diferencia-se pelo folding bounded (tamanho constante) e PQ nativo
- Tewari & Hughes (2016) — transferable ecash sem mint

### Camada 3: Compliance Sem Vigilância

**Problema**: reguladores exigem KYC/AML. Privacy coins ignoram isso e enfrentam proibições. Privacy Pools prova que fundos não são sujos, mas não prova que o UTILIZADOR é compliant.

**Solução**: credential anónima embutida no PCT que prova, sem revelar identidade:

- "O portador passou KYC num verificador aprovado"
- "O portador NÃO está em lista de sanções"
- "Esta transação está dentro dos limites regulatórios da jurisdição X"
- "O portador é maior de 18 anos"

Tudo verificável por qualquer pessoa, sem aprender NADA sobre o portador.

**Base criptográfica (abordagem faseada)**:

**Fase 1-2 (protótipo sobre curvas)**: **OpenAC** (ePrint 2026/251, Fev 2026, Ethereum PSE Lab) — anonymous credentials sem trusted setup, compatível com eIDAS 2.0, proof presentation em **0.129 segundos no mobile**, compatível com standards de Verifiable Credentials. Resolve o risco do BBS# sem precisar de pairings.

**Fase 3 (migração PQ)**: duas opções:
- Protótipo Cloudflare de credenciais anónimas PQ (Outubro 2025): 85-175KB por credential. Funcional mas grande.
- Lattice-based anonymous credentials com batch verification (ScienceDirect, 2025) + **SIS-with-Hints tight reductions** (ePrint 2026/291, Fev 2026) — reduz tamanho de credentials em 4x sobre construções anteriores (Bootle et al., CRYPTO 2023)
- **Fallback**: se nenhuma credential PQ for prática, manter OpenAC sobre curvas para a compliance layer e proteger apenas as outras camadas com PQ. A compliance credential é a parte com menor risco quântico porque é renovável (ao contrário de assinaturas de longa duração).

**Por que isto é a killer feature**:
- Para reguladores: compliance verificável sem vigilância em massa
- Para utilizadores: zero privacidade sacrificada
- Para indústria: resolve o Privacy-Compliance Paradox que bloqueia adoção há 10 anos
- Timing: eIDAS 2.0 obrigatório na UE em Setembro 2026; reguladores PRECISAM disto

Referências:
- Privacy Pools (0xbow) — live em Ethereum mainnet (Março 2025), $6M volume, 1500+ users
- zkMe — zkKYC decentralizado, integrado com TON e múltiplos DeFi
- a16z paper — "Privacy-Protecting Regulatory Solutions Using ZKPs"
- Mercado de decentralized identity projetado: $103B em 2034

### Camada 4: Offline com Garantias Económicas

**Problema**: offline total sem TEE e sem double-spend é matematicamente impossível (Trilemma formalizado, TU Munich, Dezembro 2025, arXiv:2512.10636).

**Solução**: modelo híbrido com 3 níveis de proteção:

**Nível 1 — Cryptographic Wear-Out (hash chain)**:
- Cada PCT permite N transferências offline (ex: 20-50, alinhado com o bound de recursão) antes de exigir renovação online
- Hash chain pré-commitada na emissão
- Limita o dano potencial de double-spend

**Nível 2 — VDF Time-Lock**:
- Cada PCT contém uma Verifiable Delay Function que prova "este token foi emitido/renovado há menos de T horas"
- Quando o VDF "expira", o token perde valor offline (renovável online)
- Baseado no draft IETF de Janeiro 2026 (Verifiable Delay Tokens, Bakshi, C-DAC Pune)

**Nível 3 — Reputation Bond (modelo Overdraft adaptado)**:
- Utilizadores que querem gastar offline stakeiam colateral na rede
- Receptores verificam o bond via prova incluída no PCT (sem revelar identidade)
- Se double-spend detectado: bond confiscado + identidade do fraudador revelada (blame)
- Baseado em: Overdraft (Abril 2025, Delft University, arXiv:2504.05143) — primeiro sistema que substitui hardware trust por trust económico

**AVISO**: a combinação destes 3 níveis é inédita. A segurança da composição não foi analisada formalmente. Isto é um risco e simultaneamente uma oportunidade de contribuição.

### Camada 5: Rede e Consenso

**Problema**: sem mint central, quem decide quais tokens são válidos?

**Solução**: rede P2P com consenso BFT leve:
- Nós mantêm nullifier set (lista de tokens gastos)
- Consenso apenas para: emissão e registro de tokens gastos
- Não precisa de blockchain completa — append-only log de nullifiers
- Nós incentivados com taxas mínimas de emissão/renovação

**Consenso**: HotStuff-2 (2023) ou Bullshark (2022, DAG-based BFT) — versões mais eficientes que o HotStuff original.

**DKG (Distributed Key Generation)**: necessário para as threshold keys. Protocolo de DKG lattice-based é uma área de pesquisa ativa — usar DKG clássico na fase de protótipo e migrar depois.

**Gossip-based nullifier propagation**: para detecção de double-spend eventualmente consistente em cenários offline e mesh.

---

## Stack Técnico (Corrigido)

| Componente | Tecnologia | Notas |
|---|---|---|
| Linguagem principal | **Rust** | Performance, segurança de memória, ecossistema crypto |
| Blind signatures (lattice) | **oqs-rs** + implementação custom baseada em Jeudy/Sanders | github.com/latticeblindsignature/lattice-blind-signature |
| Blind signatures (protótipo) | **curve25519-dalek** | Para protótipos iniciais sobre curvas elípticas |
| Folding/ZK proofs (PQ) | **LatticeFold+** ou **LaZer Library** | NethermindEth/latticefold (Rust, research-grade); LaZer (C, production-quality, IBM) |
| Folding/ZK proofs (protótipo) | **Nova/HyperNova** | Para Fases 0-2 sobre curvas |
| Credentials (protótipo) | **OpenAC** | ePrint 2026/251, sem trusted setup, eIDAS 2.0, 0.129s mobile |
| Credentials (PQ) | Modelo Cloudflare + SIS-with-Hints | Fallback se PQ credentials forem impráticas |
| Signatures (rede) | **HAWK-512** | NIST Round 2, 555 bytes, sem floating point |
| Hash | **SHAKE-256** | NIST standard, quantum-resistant |
| Rede P2P | **libp2p** | Madura, usada por IPFS/Filecoin/Polkadot |
| Consenso | Implementação custom de **HotStuff-2** ou **Bullshark** | |
| Serialização | **borsh** ou **protobuf** | |
| Testes | **proptest** (property-based), **criterion** (benchmarks) | |

**O que NÃO usar**:
- ~~arkworks~~ — é para curvas elípticas, não lattices
- ~~bellman~~ — específico de Groth16/Zcash
- ~~lattigo~~ — Go, não Rust
- ~~BLAZE~~ — foi quebrado
- ~~BBS+/BBS# sobre lattices~~ — não existe; usar OpenAC como bridge

---

## Papers Essenciais (Atualizado Abril 2026)

### Fundamentos (ler primeiro)
1. Chaum, "Blind Signatures for Untraceable Payments" (1983) — 4 páginas, a base de tudo
2. Shamir, "How to Share a Secret" (1979) — threshold cryptography
3. Peikert, "A Decade of Lattice Cryptography" (2016) — survey de lattices

### Estado da Arte em Blind Signatures PQ (ler na Fase 0)
4. **Jeudy & Sanders, "Improved Lattice Blind Signatures from Recycled Entropy" (CRYPTO 2025, ePrint 2024/1289)** — 36KB/sig, com implementação GitHub
5. **Agrawal et al., "Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal" (CCS 2023, ePrint 2023/077)** — 20KB/sig, round-optimal
6. **Faller, Niot & Reichle, "Lattice-based Threshold Blind Signatures" (ePrint 2025/1566)** — primeiro threshold blind PQ do mundo
7. **Baldimtsi, Goyal & Yadav, "Batched & Non-interactive Blind Signatures from Lattices" (ePrint 2025/1771)** — custo independente do batch size

### Folding, ZK Proofs PQ e Alternativas (ler na Fase 1-2)
8. **Boneh & Chen, "LatticeFold+" (CRYPTO 2025, ePrint 2025/247)** — folding PQ 5-10x mais rápido que v1
9. **Boneh & Chen, "LatticeFold" (ASIACRYPT 2025, ePrint 2024/257)** — primeiro folding lattice-based
10. **RoKoko (ePrint 2026/575)** — ~200KB proofs, 100x faster verification que Greyhound
11. **LaBRADOR (ePrint 2022/1341)** — 58KB proofs para R1CS, verifier logarítmico
12. **LaZer Library (ePrint 2024/1846, CCS 2024)** — biblioteca prática lattice ZK, IBM Research, 40-60KB proofs
13. **Holography Accumulation (ePrint 2026/538, Março 2026)** — alternativa ao folding para composição de provas; acumula verificações holográficas de polinómios

### Ecash, Transferência e Prior Art (ler na Fase 0-1)
14. Tomescu et al., "UTT: Decentralized Ecash with Accountable Privacy" (2022)
15. **Goodell et al., "Private Electronic Payments with Self-Custody and ZK-Verified Reissuance" (arXiv:2409.01958, 2024)** — tokens auto-validáveis, prior art direto
16. **Sark: "Oblivious Integrity Without Global State" (arXiv:2512.20775, Dez 2025)** — arquitetura USO, prior art arquitetural
17. **COME: "Compliant, Obliviously Managed Electronic Transfers" (arXiv:2501.10419, Jan 2025)** — compliance + oblivious money
18. Cashu NUTs specification (cashu.space) — protocolo real para estudar design modular
19. Karantaidou et al., "Blind Multisignatures for Anonymous Tokens with Decentralized Issuance" (CCS 2024)

### Compliance, Credentials e Identidade (ler na Fase 2-3)
20. **OpenAC (ePrint 2026/251, Fev 2026)** — anonymous credentials sem trusted setup, eIDAS 2.0, 0.129s mobile
21. **ePrint 2025/619, "Making BBS Anonymous Credentials eIDAS 2.0 Compliant"** — BBS# sobre curvas (referência)
22. **SIS-with-Hints tight reductions (ePrint 2026/291, Fev 2026)** — reduz tamanho de credentials lattice-based em 4x
23. **a16z, "Privacy-Protecting Regulatory Solutions Using ZKPs"** — framework conceptual
24. **Cloudflare, "Post-Quantum Anonymous Credentials" (Outubro 2025)** — protótipo PQ, 85-175KB

### Offline e Double-Spend (ler na Fase 3)
25. **"Objectives and Design Principles in Offline Payments with CBDC" (arXiv:2512.10636, Dez 2025)** — formaliza o trilemma offline
26. **Overdraft (arXiv:2504.05143, Abril 2025)** — reputation-weighted loan networks
27. **IETF Verifiable Delay Token draft (Janeiro 2026)** — VDFs para tokens com prova de tempo

### Recursão e Soundness (ler na Fase 1)
28. **Kothapalli, "A Theory of Composition for Proofs of Knowledge" (CMU-CS-24-126, 2024)** — limits de soundness em recursão IVC
29. **Collaborative IVC (ePrint 2026/410, Março 2026)** — IVC multi-prover com comunicação constante

### Threshold Signatures e Aggregação (ler na Fase 3)
30. **del Pino & Niot, "A Compact Lattice-Based Threshold Signature" (PKC 2025, ePrint 2025/872)** — threshold sig ≈ Dilithium single para T ≤ 8
31. **"Aggregating Falcon Signatures with LaBRADOR" (ePrint 2024/311, CRYPTO 2024)** — PQ signature aggregation, proof ~58KB independente do número de assinaturas
32. Lehmann et al., "Stronger Security for Threshold Blind Signatures" (EUROCRYPT 2025)

### Avançados / Group Actions e Novas Fundações (ler na Fase 4+)
33. **Tanuki (ASIACRYPT 2025, ePrint 2025/1100)** — blind signatures PQ de group actions, 3.9KB (CSIDH)
34. **LIP-based Anonymous Signatures (ePrint 2026/436)** — blind signatures a partir do Lattice Isomorphism Problem, nova fundação matemática alternativa a LWE/SIS

### Criptanálise e Ataques (ler para awareness)
35. **"Cryptanalysis of Some Lattice-Based Blind Signatures" (Fevereiro 2026)** — BLAZE quebrado
36. **"Revisiting Lattice-based Non-interactive Blind Signature" (ePrint 2025/1848)** — Zhang et al. quebrado
37. **"On the security of two blind signatures from code equivalence problems" (ePrint 2025/1883)** — LEAF quebrado

---

## Fases de Desenvolvimento (30 Meses)

### FASE 0: Fundamentos (Meses 1-3)
**Objetivo**: dominar as peças criptográficas + protótipo toy de folding

**Estudo**:
- Álgebra linear sobre corpos finitos (essencial para lattices)
- Lattices: LWE, SIS, NTRU — ler Peikert 2016
- Blind signatures: Chaum 1983 → CCS 2023 → CRYPTO 2025 (Jeudy/Sanders)
- ZK proofs: Schnorr protocol → LatticeFold paper
- Threshold: Shamir secret sharing → threshold signatures
- Prior art: ler Goodell et al. (2024) e Sark (2025) para entender o landscape

**Prática**:
- Semana 1-2: Pedersen commitment clássico sobre curvas (conceito)
- Semana 3-4: Commitment baseado em SIS (lattices)
- Semana 5-8: Schnorr blind signature em Rust (curve25519-dalek)
- Semana 9-12: Clonar e correr LatticeFold (NethermindEth) + blind signature lattice (Jeudy/Sanders) + LaZer Library

**Entregáveis**:
- Repositório GitHub com implementações de estudo
- Notas técnicas documentando cada primitivo
- Toy example de folding

### FASE 1: Protótipo PCT sobre Curvas (Meses 3-7)
**Objetivo**: proof-of-concept do PCT usando curvas elípticas (mais rápido de prototipar)

**Tarefas**:
1. Implementar threshold blind signatures sobre curvas
2. Implementar fold-on-transfer usando Nova/HyperNova (versão clássica) com bound de recursão (N=20)
3. Implementar credential anónima com **OpenAC** (eIDAS 2.0 compatible)
4. Demonstrar: token emitido → transferido N vezes → tamanho constante → verificável
5. Benchmarks de performance

**Entregáveis**:
- Biblioteca Rust: `specter-core`
- CLI para emitir, transferir e verificar PCTs
- **PREPRINT #1 no arXiv**: "Proof-Carrying Tokens: Constant-Size Transferable Ecash via Recursive Folding"

### FASE 2: Compliance Layer + Transferência Offline (Meses 7-12)
**Objetivo**: adicionar compliance privada e mecanismo offline

**Tarefas**:
1. Integrar OpenAC credential no fold (versão curvas)
2. Implementar hash chain para wear-out offline (alinhado com bound de recursão)
3. Implementar blame protocol para double-spend detection
4. Implementar nullifier set com ZK proof de não-inclusão
5. Simular cenários de ataque

**Entregáveis**:
- Transferência offline funcional (com limites)
- Compliance verificável sem revelar identidade
- Simulação de rede com 10+ nós
- **PREPRINT #2**: "Compliant Privacy: Anonymous Credentials in Bearer Tokens"

### FASE 3: Migração Pós-Quântica (Meses 12-20)
**Objetivo**: substituir TUDO por lattice-based — esta é a fase mais difícil e mais longa

**AVISO**: esta fase está estimada em 8 meses porque:
- Lattice blind signatures têm "aborting" (protocolo falha com probabilidade significativa)
- Tamanhos mudam radicalmente (32B → 20-36KB por assinatura)
- ZK proofs lattice-based são área de pesquisa ativa sem implementações maduras (exceto LaZer)
- A composição de primitivos precisa de análise de segurança (contribuição original)

**Tarefas**:
1. Substituir ECDSA por Dilithium/HAWK para assinaturas da rede
2. Substituir Pedersen commitments por lattice commitments (SIS-based)
3. Substituir blind signatures por Jeudy/Sanders ou CCS 2023
4. Substituir fold clássico por LatticeFold+ (ou LaZer + LaBRADOR como alternativa)
5. Adaptar credentials para PQ (modelo Cloudflare + SIS-with-Hints para redução 4x de tamanho)
6. Benchmark de overhead PQ vs clássico
7. Análise de segurança da composição (redução a LWE/SIS/Module-SIS)

**Entregáveis**:
- Versão PQ completa do protocolo
- Comparação: clássico vs PQ (tamanhos, tempos, failure rates)
- **SUBMISSÃO a CCS ou IEEE S&P**

### FASE 4: Offline Avançado + VDF + Bonds (Meses 20-24)
**Objetivo**: modelo offline com garantias económicas

**Tarefas**:
1. Implementar VDF time-locks nos PCTs
2. Implementar reputation bond staking
3. Implementar verificação de bond dentro do PCT (sem revelar identidade)
4. Análise game-teórica do modelo de incentivos
5. Simulação de cenários de double-spend com diferentes parâmetros

**Entregáveis**:
- Modelo offline com 3 níveis de proteção
- Análise formal de incentivos
- **PREPRINT #3**: "Offline Ecash Beyond TEE: Economic Guarantees with Cryptographic Blame"

### FASE 5: Rede P2P e Sistema Completo (Meses 24-28)
**Objetivo**: sistema funcional descentralizado

**Tarefas**:
1. Implementar protocolo P2P (libp2p)
2. Implementar consenso BFT (HotStuff-2 ou Bullshark)
3. Implementar DKG para threshold keys
4. Implementar mecanismo de incentivo para nós
5. Testnet com nós distribuídos
6. Wallet CLI completa

**Entregáveis**:
- Testnet funcional
- Wallet CLI
- Especificação modular do protocolo (estilo NUTs do Cashu — specs numeradas, implementáveis independentemente)

### FASE 6: Publicação e Lançamento (Meses 28-30)
**Objetivo**: impacto

**Tarefas**:
1. Escrever paper formal principal (target: CRYPTO ou EUROCRYPT)
2. Self-audit de segurança formal + convite à comunidade
3. Lançar código open source (licença MIT ou Apache 2.0)
4. Publicar especificação do protocolo
5. Apresentar em conferência (Real World Crypto, Financial Cryptography)

**Entregáveis**:
- Paper submetido a conferência tier-1
- Repositório público com documentação completa
- Website do projeto com spec

---

## Timeline Visual

```
2026
Jun-Ago  ████ FASE 0: Fundamentos + toy folding + ler prior art
Set-Jan  █████ FASE 1: PCT sobre curvas + OpenAC → PREPRINT #1

2027
Fev-Jun  █████ FASE 2: Compliance + offline → PREPRINT #2
Jul-Fev  ████████ FASE 3: Migração PQ total → SUBMISSÃO CCS/S&P

2028
Mar-Jun  ████ FASE 4: VDF + bonds + offline avançado → PREPRINT #3
Jul-Out  ████ FASE 5: Rede P2P + testnet + spec modular
Nov-Dez  ██ FASE 6: Paper principal + lançamento

Total: ~30 meses
```

**Estratégia de publicação incremental**: preprint a cada ~5 meses. Planta bandeira cedo. Torna impossível ser scooped silenciosamente.

---

## Papers Publicáveis (5 Potenciais)

| # | Título | Target | Fase |
|---|---|---|---|
| 1 | "Proof-Carrying Tokens: Constant-Size Transferable Ecash via Recursive Folding" | ACM CCS | 1 |
| 2 | "Compliant Privacy: Anonymous Credentials Folded into Bearer Tokens" | IEEE S&P | 2 |
| 3 | "Post-Quantum Ecash at Scale: A LatticeFold+ Recursive Construction" | CRYPTO | 3 |
| 4 | "Offline Digital Cash with Economic Guarantees: Beyond the TEE Assumption" | Financial Crypto | 4 |
| 5 | "Specter: A Complete Decentralized PQ Ecash Protocol with Private Compliance" | EUROCRYPT | 6 |

---

## Financiamento e Caminhos Institucionais

### Grants Disponíveis

**NGI TALER (NLnet Foundation)** — EUR 5K-50K por projeto
- Foco: "technology commons for privacy-friendly digital payments"
- Próximo deadline: **1 de Junho 2026**
- Specter como complemento à infraestrutura GNU Taler
- Site: nlnet.nl/taler

**Horizon Europe PET Call** — EUR 3-4M por projeto
- O scope LITERALMENTE descreve o que estamos a construir: "blockchain-based decentralized PETs... crypto-agile... post-quantum... anonymous credentials"
- Call 2025 encerrado; successor calls esperados no Work Programme 2026-2027 (EUR 14B total)
- Site: cordis.europa.eu

**Ethereum Foundation Academic Grants** — até $1.5M total por ronda
- Cobre: PQ cryptography, ZK tooling, applied cryptography
- Requer output open source
- Site: esp.ethereum.foundation/academic-grants

**MSCA Postdoctoral Fellowships 2026**
- Abre Abril 2026, deadline Setembro 2026
- Tópicos elegíveis incluem "post-quantum cryptography" e "privacy"
- 12-24 meses com salário competitivo
- Hostável em universidade europeia (ex: Granada)

### Caminhos Institucionais

**OpenCBDC (MIT DCI)** — issue aberta #49 para integração de blind signatures. Contribuir com o approach Specter criaria credibilidade institucional.

**BIS Innovation Hub Swiss Centre** — onde Project Tourbillon foi feito. Aberto a propostas de PQ privacy para CBDC.

**GNU Taler** — ecash Chaumiano operacional na Suíça desde 2025. Specter poderia ser posicionado como a camada PQ para a infraestrutura Taler.

---

## Relevância para CBDCs

### O Que os Bancos Centrais Testaram e Onde Falharam

**Project Tourbillon** (BIS + SNB + David Chaum, 2023): construiu dois protótipos de ecash com blind signatures, incluindo lattice-based PQ. **Resultado: throughput reduziu 200x com PQ.** Provou a demanda mas demonstrou que a performance PQ é o bottleneck.

**Project Leap Phase 2** (BIS, Dez 2025): testou Dilithium PQ no sistema TARGET2. **Resultado: assinaturas 12.9x maiores** (3,293 bytes vs 256), latência aumentou significativamente.

**ECB Digital Euro** (Outubro 2025): escolheu **pseudonimização** em vez de privacidade criptográfica. Sem blind signatures, sem ZKPs. Privacidade institucional (access control), não matemática.

### Onde Specter Encaixa

Se Specter demonstrar melhor performance PQ que Tourbillon (mesmo 10x melhor seria notável), o sistema entra automaticamente no radar da comunidade de pesquisa de CBDCs. O LatticeFold+ recursive compression é exatamente o tipo de otimização que poderia fechar o gap de performance PQ.

O **BIS quantum-readiness roadmap** (Julho 2025, BIS Papers 158) estabelece:
- RSA deprecated by 2030, prohibited by 2035
- Migrações PQ a decorrer no final dos anos 2020
- Specter estaria maduro (2028-2029) exatamente quando as migrações começam

---

## Princípios de Design

Baseado na análise de projetos que se tornaram referência (Zcash, Tor, Signal, Cashu, Let's Encrypt, WireGuard), os princípios para maximizar impacto:

1. **Simplicidade acima de tudo.** A spec deve ser legível por um developer competente em 1-2 horas. O Cashu ganhou ao Fedimint por ser mais simples. WireGuard ganhou ao OpenVPN com 4K linhas vs 100K.

2. **Spec modular.** Inspirada nos NUTs do Cashu e BIPs do Bitcoin: specs numeradas, cada uma implementável independentemente. Isto permite que múltiplos developers criem implementações, criando ecossistema em vez de monólito.

3. **Publicar incrementalmente.** Preprints a cada 5 meses + código público desde o dia 1. Estabelecer prioridade e criar feedback loop.

4. **Dizer NÃO.** Não adicionar features especulativas. Não tentar resolver todos os problemas. O PCT + compliance + PQ + offline bounded é ambicioso o suficiente. Cada feature adicional dilui o foco.

5. **Framing como infraestrutura, não produto.** "Protocolo de dinheiro digital privado e seguro" — modelo Tor. Pesquisa + código open source, não serviço.

---

## Riscos e Mitigações

### Risco 1: Lattice blind signatures podem ser ineficientes demais
**Probabilidade**: Média
**Mitigação**: começar com curvas elípticas (Fases 0-2). Se lattices forem impraticáveis, publicar versão clássica + análise de viabilidade PQ. Paper publicável em qualquer caso.

### Risco 2: Composição de 5 primitivos lattice-based sem análise unificada
**Probabilidade**: Alta — NINGUÉM fez esta análise
**Mitigação**: este risco é simultaneamente a maior oportunidade. A análise de segurança da composição É uma contribuição original. Usar LaZer Library (IBM) como base reduz risco porque o LaZer tem análise de segurança interna mais madura. Começar com composição de 2 primitivos e expandir incrementalmente.

### Risco 3: Alguém publica algo parecido antes
**Probabilidade**: 20%
**Mitigação**: publicar incrementalmente. Preprints a cada ~5 meses. Código no GitHub desde o dia 1. O grupo Goodell (UCL) é o mais próximo — considerar contacto proactivo para colaboração.

### Risco 4: Complexidade demais para uma pessoa
**Probabilidade**: Alta
**Mitigação CRÍTICA**: encontrar co-autor ou orientador com expertise em lattice crypto. Em Granada, procurar dentro do departamento de matemática/criptografia. Candidatar a MSCA fellowship ou grant que forneça funding para colaboração.

### Risco 5: LatticeFold+ não é maduro o suficiente
**Probabilidade**: Média — implementação NethermindEth é research-grade
**Mitigação**: LaZer Library (IBM) como alternativa para provas individuais. Holography Accumulation (ePrint 2026/538) como alternativa ao folding se necessário. Contribuir para implementações existentes.

### Risco 6: Profundidade de recursão limitada degrada UX
**Probabilidade**: Baixa-Média
**Mitigação**: bound de N=20-50 transferências é generoso para uso real. A renovação online pode ser automatizada (wallet faz background renewal quando tem conectividade). Na prática, cash físico também "precisa de ir ao banco" periodicamente.

### Risco 7: Tokens de 300-600KB são grandes demais para adoção
**Probabilidade**: Média
**Mitigação**: posicionar para transferências de valor médio/alto, não micropagamentos. 300KB é viável para mobile (uma foto de smartphone é 3-5MB). A tendência de redução de provas lattice-based é consistente (papers de 2026 já mostram melhorias significativas).

### Risco 8: Legal
**Probabilidade**: Baixa
**Mitigação**: publicar como pesquisa acadêmica. Não operar serviço. Modelo Tor. A camada de compliance é argumento a favor.

---

## Avaliação Honesta

### Scores Realistas

| Critério | Score | Justificação |
|---|---|---|
| Inovação | **8/10** | Aplicação inédita de primitivos novíssimos; prior art existe (Sark) mas sem PQ/folding/compliance |
| Impacto académico | **8/10** | 3-5 papers tier-1 realista com execução forte |
| Impacto industrial | **7/10** | Necessidade real; tokens 300-600KB limitam uso; CBDC path aumenta potencial |
| "Abalar a comunidade" | **7/10** | Prior art de Goodell mostra que a comunidade já pensa nisto; Specter seria a versão PQ definitiva |
| Probabilidade de referência | **15-25%** | Real, não garantido. CBDC path e funding europeu aumentam chances vs avaliação anterior |
| Risco de falha | **25%** | Reduzido vs anterior (30%) pela descoberta de LaZer, OpenAC, e Holography Accumulation como fallbacks |
| Impacto na carreira | **9/10** | Mesmo no cenário pessimista, portfólio de elite |

### Cenários

| Cenário | Probabilidade | Resultado |
|---|---|---|
| 2-3 papers, código open source, tese forte | **50%** | Carreira académica sólida, reconhecimento na comunidade PQ |
| Alguém publica antes, mas o teu código tem valor | **15%** | Publicável como implementação independente |
| Vira referência real ("o ecash PQ") | **15-25%** | Convites para conferências, financiamento, posição de investigação |
| Specter benchmarks superam Tourbillon → interesse de CBDCs | **10-15%** | Financiamento institucional, colaboração com BIS/ECB |
| Falha técnica (primitivos não compõem) | **10%** | Publicável como negative result + análise de viabilidade |

### Por Que Compensa
- No pior cenário absoluto: 1 paper + expertise rara em lattice crypto
- No cenário mediano (50%): 2-3 papers tier-1 + portfólio de elite
- No cenário bom (15-25%): referência que define uma subárea
- No cenário excelente (10-15%): relevância institucional (CBDCs, BIS)
- **Não existe projecto com melhor relação risco/recompensa para investir 30 meses**

---

## Primeiros 7 Dias

**Dia 1**: Ler Chaum 1983 (4 páginas). Instalar Rust. Ler o abstract e introdução do LatticeFold+ (ePrint 2025/247).

**Dia 2**: Ler Shamir 1979 (6 páginas). Implementar Shamir Secret Sharing em Rust.

**Dia 3**: Ler o paper CCS 2023 (Agrawal et al.) — "Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal." Clonar o repo de Jeudy/Sanders (github.com/latticeblindsignature/lattice-blind-signature).

**Dia 4**: Ler spec do Cashu (cashu.space/specs) — estudar design modular das NUTs. Ler Goodell et al. 2024 (arXiv:2409.01958) — entender prior art de tokens auto-validáveis.

**Dia 5**: Ler Tanuki (ASIACRYPT 2025) — introdução + tabelas. Implementar Schnorr blind signature clássica em Rust (curve25519-dalek).

**Dia 6**: Clonar LatticeFold (github.com/NethermindEth/latticefold). Compilar, correr exemplos. Explorar LaZer Library (ePrint 2024/1846).

**Dia 7**: Criar repositório `specter-protocol`. Escrever README com visão honesta. Publicar implementações de estudo. Aplicar a NGI TALER (deadline 1 Junho 2026) se timing permitir.

---

## Contexto Competitivo (Abril 2026)

### Projetos PQ Relevantes (Nenhum é Ecash Privado)
- **Algorand**: primeira transação PQ em mainnet (Falcon-1024, Nov 2025) — transparente, sem privacidade
- **Bitcoin BIP-360**: SHRIMPS hash-based PQ signatures (~2.5KB) — em testnet, sem privacidade
- **QRL**: migrando para SPHINCS+ — sem privacidade
- **Zcash**: roadmap PQ publicado, mas admite que proofs explodem 1000x em Halo 2

### Projetos de Privacidade (Nenhum é PQ)
- **Aztec Alpha** (Março 2026): primeiro L2 privado em Ethereum — 1 TPS, não PQ
- **Namada** (Dezembro 2024): MASP multi-asset — não PQ
- **Privacy Pools** (Março 2025): compliance sem vigilância — não PQ, não ecash
- **Cashu/Fedimint**: ecash funcional — centralizado/federado, não PQ

### Prior Art Direto (Nenhum é PQ + Folding + Compliance)
- **Sark/USO** (Goodell, UCL, Dez 2025): tokens auto-verificáveis sem ledger — não PQ, tamanho cresce linearmente
- **COME Protocol** (Goodell, UCL, Jan 2025): compliance oblivious — não PQ, sem folding

### Projetos CBDC com Privacidade (Nenhum é PQ + Prático)
- **Project Tourbillon** (BIS + SNB): testou PQ blind signatures, 200x throughput reduction
- **GNU Taler**: ecash Chaumiano operacional, não PQ
- **Digital Euro** (ECB): pseudonimização, não privacidade criptográfica

### A Posição de Specter
Specter seria o **primeiro sistema no mundo** a combinar PQ + privacidade + compliance + descentralização + tamanho constante bounded. Prior art existe (Sark/USO) mas sem PQ, folding, ou compliance embedded. A diferenciação é clara e verificável.

---

## Siglas e Glossário

- **PCT**: Proof-Carrying Token — a inovação central
- **PQ**: Pós-Quântico — resistente a computadores quânticos
- **LWE**: Learning With Errors — problema hard em lattices
- **SIS**: Short Integer Solution — problema hard em lattices
- **MSIS/MLWE**: Module-SIS/Module-LWE — variantes modulares (base de Dilithium/Kyber)
- **BFT**: Byzantine Fault Tolerant — consenso que tolera nós maliciosos
- **DKG**: Distributed Key Generation — geração de chaves entre múltiplos nós
- **VDF**: Verifiable Delay Function — prova de passagem de tempo
- **IVC**: Incrementally Verifiable Computation — computação verificável recursiva
- **MASP**: Multi-Asset Shielded Pool — pool privada multi-ativos
- **ASP**: Association Set Provider — provedor de listas de compliance
- **eIDAS**: Electronic Identification, Authentication and Trust Services — regulação EU
- **USO**: Unforgeable, Stateful, Oblivious — modelo de Goodell para assets digitais
- **OpenAC**: Open Anonymous Credentials — credenciais anónimas sem trusted setup (Ethereum PSE Lab)
- **LaZer**: Lattice-based Zero-knowledge — biblioteca prática da IBM Research
