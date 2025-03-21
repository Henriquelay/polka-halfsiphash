// #import "@preview/touying:0.6.1": *
#import "@preview/fletcher:0.5.7" as fletcher: diagram, node, edge, shapes
#import "@preview/minideck:0.2.1"
#import "@preview/bytefield:0.0.7": *

#let (template, slide, title-slide, fletcher-uncover, fletcher-only, pause, uncover, only) = minideck.config(
  theme: minideck.themes.simple,
  paper: "16:9",
  fletcher: fletcher,
)
#show: template

// #set cite(form: "prose")
// #show cite: it => [(#it)]
#set text(font: "New Computer Modern")
#set par(justify: true)

#show "pathsec": "PathSec"
#show "pathSec": "PathSec"
#show "Pathsec": "PathSec"
#show "polka": "PolKA"
#show "timestamp": `timestamp`
#show "lhash": `l_hash`
#show "nodeid": `nodeID`
#show "routeid": `route_id`
#show "portid": `portID`
#show "portId": `portID`
#show "Pie": $limits(P)_(i->e)$
#show "Pj": $P_j$

// Shadow diagram to use default settings
#let diagram = diagram.with(
  node-inset: 0.2em,
  axes: (ltr, btt),
)

#let edge_node = node.with(fill: aqua, shape: shapes.pill, stroke: 0.5pt)
#let core_node = node.with(fill: lime, shape: shapes.pill, stroke: 0.5pt)
#let host_node = node.with(fill: white, shape: shapes.rect, stroke: 0.5pt)
#let controller_node = node.with(fill: orange, shape: shapes.diamond, stroke: 0.5pt)
#let nodetext = text.with(baseline: -0.1em)
#let topocolumn(loc, n) = {
  host_node(loc, nodetext[$h_#n$], name: label("h" + str(n)))
  edge()
  edge_node((rel: (0, 1)), nodetext[$e_#n$], name: label("e" + str(n)))
  edge()
  core_node((rel: (0, 1)), nodetext[$c_#n$], name: label("c" + str(n)))
}
#let topo(n_node, start: 1, loc: ()) = {
  topocolumn(loc, start)
  for n in range(start + 1, n_node + start) {
    topocolumn((rel: (1, 0), to: label("h" + str(n - 1))), n)
    edge(label("c" + str(n - 1)), label("c" + str(n)))
  }
}

#let title = "Implementing and Testing a Probing-Based Path Verification for PolKA Source Routing Protocol"
#let titulo = "Implementação e Teste de uma Verificação de Rota Baseada em Amostragem para o Protocolo de Roteamento em Origem PolKA"

////////////////////////////////////
// START

#title-slide[
  #show footnote.entry: it => align(left, text(0.6em, it))

  #text(size: 17pt, title)
  = #text(size: 30pt, titulo)

  #v(5fr)

  #set text(size: 15pt)
  #set align(left)

  Henrique Coutinho Layber
  #v(1fr)
  Orientadores: Roberta Lima Gomes, Magnos Martinello

  Universidade Federal do Espírito Santo
  #h(1fr)
  20 de Março de 2025
]

#slide(steps: 2)[
  == Contexto

  Em sistemas de Roteamento em Origem (SR), normalmente implementados em Redes Definidas por Software (SDNs)@SRSDN o nó de entrada define a rota que o pacote deve seguir.

  #show: pause

  Há uma necessidade de verificar que o pacote seguiu a rota definida pelo nó de entrada, não apenas por questões de segurança, mas também para garantir que a rede esteja funcionando corretamente e configurada adequadamente.
]

#slide(steps: 4)[
  == Apresentação do Problema
  Assuma um pacote $h_1 -> h_3$:

  1. A rota é definida pelo nó de entrada (_ingress node_)
  #uncover(from: 2)[
    2. ???
  ]
  #uncover(from: 3)[
    3. O pacote chega ao nó de destino (_egress node_)
  ]



  #context diagram(
    spacing: (2cm, 0.01cm),
    // debug: 1,
    {
      topo(3)

      core_node((rel: (0, 0.8), to: <c2>), nodetext[$c_4$], name: <c4>)
      edge(<c1>)
      edge(<c3>)


      fletcher-uncover(
        from: 1,
        {
          node(
            (rel: (-1, 1), to: <e1>),
            [Define a rota\ $(c_1, c_4, c_3)$],
            name: <anotacao1>,
          )
          edge(<anotacao1>, "}>-}>", <e1>)
        },
      )
      fletcher-uncover(
        from: 3,
        {
          node(
            (rel: (1, 1), to: <e3>),
            [Pacote chega em $e_3$],
            name: <anotacao2>,
          )
          edge(<anotacao2>, "}>-}>", <e3>)
        },
      )

      fletcher-uncover(
        from: 4,
        {
          node(
            (rel: (1, 0), to: <h3>),
            [Como garantir que\ $"rota realizada" = (c_1, c_4, c_3)$?],
          )
        },
      )
    },
  )
]

#slide(steps: 10)[
  == Formalizando o Problema

  Rota definida Pie é a sequência de nós $s_d$: $(s_d_1, s_d_2, dots, s_d_n)$.\
  #show: pause
  Rota realizada Pj é a sequência de nós $s_r$ coletada $(s_r_1, s_r_2, dots, s_r_n)$.\
  #show: pause
  Precisamos simplesmente verificar se $"Pie" = "Pj"$

  // #set text(size: 0.9em)
  #show: pause
  Os nós estão corretos: $(c_1, c_4, c_3) != (c_1, c_2, c_3)$\
  #show: pause
  Não há nós a mais: $(c_1, c_4, c_3) != #only(5)[$(c_1, c_4, c_4, c_3)$]$
  #show: pause
  #text(fill:red)[$(c_1, c_4, c_4, c_3)$]#only(6,[Validade não interessa])\
  #show: pause
  Não há nós a menos: $(c_1, c_4, c_3) != (c_1, c_3)$\
  #show: pause
  Os nós estão na ordem correta: $(c_1, c_4, c_3) != (c_4, c_1, c_3)$\
  #show: pause
  *Não é preciso conhecer os elementos da sequência!*
]

#slide(steps: 2)[
  == Solução proposta

  pathsec@pathsec: Sugere uma solução baseada em amostragem como uma extensão do polka, alguns pacotes se tornam sondas, e recebem os campos adicionais de timestamp e lhash. É usada uma composição de funções com um hash criptográfico, baseada no _Hash-based Message Autentication Code_ (HMAC).

  #show: pause

  Isso define um modelo de multiassinatura. O controlador conhece os segredos dos nós (nodeid) e calcula a assinatura final de Pie após o _ingress edge_ enviar os metadados, e o _egress edge_ captura a assinatura final de Pj.
]
#slide(steps: 1)[
  == Solução proposta

  $"lhash"_0 = "timestamp"$

  $"lhash"_n = "Hash"("nodeid"_c_n || "portid"_n || "lhash"_(n-1) )$
]

#slide(steps: 6)[

  #set align(horizon + center)
  #context diagram(
    spacing: (1cm, 0.2cm),
    // debug: 1,
    {
      topo(3)
      core_node((rel: (0, 1), to: <c2>), nodetext[$c_4$], name: <c4>)
      edge(<c1>)
      edge(<c3>)

      // Controller
      let routeid = `0x01A4`
      let timestamp = `0x3241`
      let lhash_certo = `0xa39b`
      let lhash_errado = `0x3b26`

      controller_node(
        (rel: (0, 1), to: <c4>),
        nodetext[controller],
        name: <controller>,
      )
      edge(crossing: true, <e2>, bend: 25deg)
      edge(crossing: true, <e3>)


      fletcher-uncover(1, from: 3, edge(crossing: true, <controller>, <e1>))
      fletcher-uncover(
        1,
        {
          node(
            (rel: (-1, 1), to: <e1>),
            [
              Define a rota\ $(c_1, c_4, c_3)$\
              `routeid = `#routeid\
              `timestamp = `#timestamp\
            ],
            name: <anotacao1>,
          )

          edge(<anotacao1>, "}>-}>", <e1>)
        },
      )
      fletcher-uncover(
        2,
        {
          node(
            (rel: (-1, 1), to: <e1>),
            [
              Envia metadados\ ao controlador\
              (e também ao core)
            ],
            name: <anotacao2>,
          )
          edge(
            crossing: true,
            <e1>,
            <controller>,
            label: text(size: 0.7em)[`routeid = `#routeid\
              `timestamp = `#timestamp],
            label-pos: 0.8,
          )
        },
      )
      fletcher-uncover(
        3,
        {
          node(
            (rel: (-1, 1), to: <e1>),
            [
              Enquanto o controlador\ calcula a assinatura\
              de ref., o core calcula\ a assinatura nativamente

            ],
            name: <anotacao3>,
          )
          node(
            (-1, 4),
            text(size: 20pt)[ $"lhash"_n = "Hash"("nodeid", ..., "lhash"_(n-1))$],
          )
        },
      )
      fletcher-uncover(
        4,
        {
          node(
            (rel: (-1, 1), to: <e1>),
            [
              $c_1: H(#timestamp||"node_id"_c_1...) = $`0xc206`\
              $c_4: H($`0xc206`$||"node_id"_c_4...) = $`0xe71f`\
              $c_3: H($`0xe71f`$||"node_id"_c_3...) = $#lhash_certo\
            ],
          )
          edge("--", <controller>)
          node(
            (-1, 4),
            text(size: 20pt)[
              $"lhash"_n = "Hash"("nodeid", "portid", "lhash"_(n-1))$\
              timestamp = #timestamp routeid = #routeid],
          )
        },
      )
      fletcher-uncover(
        5,
        {
          node(
            (rel: (-1, 2), to: <e1>),
            [
              Os resultados são enviados ao smart contract\
            ],
            name: <anotacao51>,
          )
          node(
            (rel: (-1, 1), to: <e1>),
            shape: shapes.house,
            stroke: 0.5pt,
            name: <blockchain>,
            [#emoji.chain#emoji.cabinet],
          )
          edge(<blockchain>, <controller>, "<{--", bend: -20deg)
          edge(<blockchain>, <e3>, "<{--", crossing: true)

          node(
            (rel: (0, -0.6), to: <blockchain>),
            align(
              right,
              text(size: 18pt)[
                Controller: {`flow_id`: #timestamp, lhash: #lhash_certo}\
                Egress: {`flow_id`: #timestamp, lhash: #text(fill:red, lhash_errado)}\
              ],
            ),
            name: <anotacao52>,
          )
        },
      )
      fletcher-uncover(
        6,
        {
          node(
            (rel: (-1, 1), to: <e1>),
            [
              $c_1: H(#timestamp||"node_id"_c_1...) = $`0xc206`\
              $c_2: H($`0xc206`$||"node_id"_c_2...) = $`0xb38f`\
              $c_3: H($`0xb38f`$||"node_id"_c_3...) = $#text(fill:red, lhash_errado)
            ],
          )
          edge(<arrow>, "--")
          node(
            (-1, 4),
            text(size: 20pt)[
              $"lhash"_n = "Siphash"(\
                  "nodeid" || "portid" || "timestamp" || 0000000, "lhash"_(n-1))$\
              timestamp = #timestamp routeid = #routeid],
          )
          node(
            (rel: (0, 0.5), to: <c2>),
            name: <arrow>,
            text(size: 50pt, sym.arrow.r.squiggly),
          )
        },
      )
    },
  )
  #align(
    bottom + right,
    text(size: 0.6em)[
      Valores ilustrativos.
    ],
  )
]

#slide(steps: 2)[
  == Implementando

  Foi extendido de um projeto de polka em P4 já existente@polkap4. O Mininet-wifi@mininet-wifi foi usado para simular a rede. Scapy@scapy foi usado para fazer _sniffing_ dos pacotes trafegados.\
  Foi utilizado um hash criptográfico _Siphash-c-d_, mais especificamente `SipHash-2-4-32`@siphash, ou seja, $2$ _$c$-rounds_ e $4$ _$d$-rounds_, com uma chave de 64bits e entrada de 32bits.

  #show: pause

  $"lhash"_n = $`SipHash-2-4-32`$(overshell("nodeid"_c_n, "16b")||overshell("portid"_n, "9b")||overshell("timestamp", 32b)||overshell("0000000", 7b), overshell("lhash"_(n-1), 32b) )$
]



#slide(steps: 4)[
  == _SipHash_, _$c$-rounds_ e _$d$-rounds_

  _SipHash_ é um algoritmo baseado em _Add-Rotate-Xor_ (ARX) (BLAKE, ChaCha20, etc), e uma sequência específica de operações ARX é chamado de _SipRound_.

  #show: pause
  $c$ é o número iterações _SipRounds_ entre cada ingestão de um novo bloco.

  #show: pause
  $d$ é o numero iterações _SipRounds_ após ingerir todos os blocos, e antes de produzir a saída.

  #show: pause
  _SipHash_ garante a máxima segurança MAC para $c >= 2; d >= 4$@siphash.
]


#slide[

  #bytefield(
    bpr: 64,
    // Config the header
    bitheader(
      "bytes",
    ),

    group(right, 3)[PolKA],
    bytes(1, fill: green.lighten(30%))[`version`],
    bytes(1, fill: green.lighten(30%))[`ttl`],
    bytes(2, fill: purple.lighten(30%))[`proto`],
    bits(160, fill: green.lighten(30%))[routeid],
    note(right)[Sonda\ Pathsec],
    bytes(4, fill: teal.lighten(30%))[timestamp],
    bytes(4, fill: teal.lighten(30%))[lhash],
  )
]

#let diagram = diagram.with(spacing: (1cm, 1cm))
#slide[
  == Testes

  Partindo de uma topologia base


  #align(
    center,
    context diagram({
      topo(10)
      host_node((-1, 0), nodetext[$h_11$], name: <h11>)
      edge(<e1>)
    }),
  )

  Foram testadas as seguintes condições:
]

#slide[
  == Testes

  === Adição
  #align(
    center + horizon,
    context diagram({
      topo(5)
      host_node((-1, 0), nodetext[$h_11$], name: <h11>)
      edge(<e1>)

      core_node((rel: (1, 1), to: <c5>), nodetext[$c_"add"$], name: <cadd>)
      edge(<c5>)
      edge(<c6>)
      topo(5, start: 6, loc: (rel: (2, 0), to: <h5>))
    }),
  )
]

#slide[
  == Testes

  === Salto
  #align(
    center + horizon,
    context diagram({
      topo(4)
      edge(<c6>)
      topo(5, start: 6, loc: (rel: (1, 0), to: <h4>))
      host_node((-1, 0), nodetext[$h_11$], name: <h11>)
      edge(<e1>)
    }),
  )
]

#slide[
  == Testes

  === Desvio
  #align(
    center + horizon,
    context diagram({
      topo(10)
      core_node((rel: (1, 1), to: <c5>), nodetext[$c_"det"$], name: <cdet>)
      edge(<c5>, "<-")
      edge(<c7>, "->")
      edge(<c7>, "->", <c6>)
      edge(<c6>, "->", <c5>)
      host_node((-1, 0), nodetext[$h_11$], name: <h11>)
      edge(<e1>)
    }),
  )
]

#slide[
  == Testes

  === Fora de ordem
  #align(
    center + horizon,
    context diagram({
      topo(4)
      topocolumn((rel: (1, 0), to: <h4>), 6)
      edge(<c4>)
      edge(<c5>)
      topocolumn((rel: (1, 0), to: <h6>), 5)
      edge(<c7>, <c5>)
      topo(3, start: 7, loc: (rel: (1, 0), to: <h5>))
      host_node((-1, 0), nodetext[$h_11$], name: <h11>)
      edge(<e1>)
    }),
  )
]

#slide[
  == Resultados
  Para um pacote $h_1 -> h_10$ foram observados os seguintes resultados de lhash intermediários:

  (routeid = `0x707b3a1d61d1d0d8b9fc91e442d0360dfc8bba4`)

]

#slide[
  #set align(center + horizon)

  #let redc = table.cell.with(fill: red.lighten(5%))

  //Set text size only for `code` text, leaving rest of the text with default size

  #set text(size: 0.8em)
  #table(
    columns: (auto, auto, auto, auto, auto, auto, auto, auto, auto, auto),
    stroke: none,
    inset: (
      x: 4pt,
      y: 5pt,
    ),
    table.hline(),
    table.header(
      table.cell(colspan: 2)[Referência],
      table.vline(),
      table.cell(colspan: 2)[Adição],
      table.vline(),
      table.cell(colspan: 2)[Salto],
      table.vline(),
      table.cell(colspan: 2)[Desvio],
      table.vline(),
      table.cell(colspan: 2)[Fora de ordem],
    ),
    table.hline(),

    $e_1$, `0x61e8d6e7`, $e_1$, `0x61e8d6e7`, $e_1$, `0x61e8d6e7`, $e_1$, `0x61e8d6e7`, $e_1$, `0x61e8d6e7`,
    $c_1$, `0xd25dc935`, $c_1$, `0xd25dc935`, $c_1$, `0xd25dc935`, $c_1$, `0xd25dc935`, $c_1$, `0xd25dc935`,
    $c_2$, `0x245b7ac5`, $c_2$, `0x245b7ac5`, $c_2$, `0x245b7ac5`, $c_2$, `0x245b7ac5`, $c_2$, `0x245b7ac5`,
    $c_3$, `0xa3b38b83`, $c_3$, `0xa3b38b83`, $c_3$, `0xa3b38b83`, $c_3$, `0xa3b38b83`, $c_3$, `0xa3b38b83`,
    $c_4$, `0x26aee736`, $c_4$, `0x26aee736`, $c_4$, `0x26aee736`, $c_4$, `0x26aee736`, $c_4$, `0x26aee736`,
    $c_5$, `0xf9b47914`, $c_5$, `0xf9b47914`, [], [], $c_5$, `0xf9b47914`, redc[$c_6$], redc[`0x4b5a6c5a`],
    [], [], redc[$c_"add"$], redc[`0x250822a2`], [], [], [], [], [], [],
    $c_6$, `0x18c6d8d1`, redc[$c_6$], redc[`0x20d21d49`], redc[$c_6$], redc[`0x4b5a6c5a`], redc[$c_"det"$], redc[`0x250822a2`], redc[$c_5$], redc[`0xde3862a0`],
    $c_7$, `0xb69b99ec`, redc[$c_7$], redc[`0xdd03c4c2`], redc[$c_7$], redc[`0x002346d3`], redc[$c_7$], redc[`0x40298bb9`], redc[$c_7$], redc[`0x648556ec`],
    $c_8$, `0xfe6117f8`, redc[$c_8$], redc[`0x292e8608`], redc[$c_8$], redc[`0x7ec711aa`], redc[$c_8$], redc[`0xe13dcc9b`], redc[$c_8$], redc[`0x144e1d1b`],
    $c_9$, `0xc8d9fbde`, redc[$c_9$], redc[`0x32419384`], redc[$c_9$], redc[`0x5ee32b7b`], redc[$c_9$], redc[`0x1bf62c19`], redc[$c_9$], redc[`0x9e818f34`],
    table.hline(),
    $c_"10"$, `0xa6293a25`, redc[$c_"10"$], redc[`0xf4bcdf07`], redc[$c_"10"$], redc[`0xc973a219`], redc[$c_"10"$], redc[`0xdd3a6675`], redc[$c_"10"$], redc[`0x6f694bc`],
    table.hline(),
  )
]

#title-slide[
  = Perguntas?

  #align(bottom + left)[
    Henrique Coutinho Layber

    #link("https://github.com/Henriquelay/polka-halfsiphash")
  ]

]


#slide[
  #bibliography("../TCC2/bibliography.bib")
]


// == Base topology
// #diagram({
//   topo(10)
//   host_node(
//     (rel: (-1, 0), to: <h1>),
//     nodetext($h_(11)$),
//     name: <h11>,
//   )
//   edge(<h11>, <e1>)
// })
