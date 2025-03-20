// #import "@preview/touying:0.6.1": *
#import "@preview/fletcher:0.5.7" as fletcher: diagram, node, edge, shapes
#import "@preview/minideck:0.2.1"
#import "@preview/bytefield:0.0.7": *

#let (template, slide, title-slide, fletcher-uncover, pause, uncover, only) = minideck.config(
  theme: minideck.themes.simple,
  paper: "16:9",
  fletcher: fletcher,
)
#show: template

#set cite(form: "prose")
#show cite: it => [(#it)]
#set text(font: "New Computer Modern")

#show "pathsec": "PathSec"
#show "pathSec": "PathSec"
#show "Pathsec": "PathSec"
#show "timestamp": `timestamp`
#show "lhash": `l_hash`
#show "nodeid": `node_id`
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
    edge(label("c" + str(n - 1)), label("c" + str(n)), "-")
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

  #v(1fr)

  #set text(size: 15pt)
  #set align(left)

  Henrique Coutinho Layber #footnote[#link("mailto:henrique.layber@edu.ufes.br")]

  Orientadores: Roberta Lima Gomes#footnote[#link("mailto:roberta.gomes@ufes.br")], Magnos Martinello#footnote[#link("mailto:magnos.martinello@ufes.br")]

  Universidade Federal do Espírito Santo
  #h(1fr)
  20 de Março de 2025
]

#slide[
  == Contexto

  Em sistemas de Roteamento em Origem (SR), normalmente implementados em Redes Definidas por Software (SDNs)@SRSDN o nó de origem define a rota que o pacote deve seguir. Há uma necessidade de garantir que o pacote siga a rota definida pelo nó de origem, não apenas por questões de segurança, mas também para garantir que a rede esteja funcionando corretamente e configurada adequadamente.
]

#slide(steps: 4)[
  == Apresentação do Problema
  Assuma um pacote $h_1 -> h_3$:

  1. A rota é definida pelo nó de origem (_ingress node_)
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
      topocolumn((), 1)
      edge()
      core_node((rel: (1, 0.7)), nodetext[$c_4$], name: <c4>)
      topocolumn((rel: (1, 0), to: <h1>), 2)
      edge(<c1>, "-")
      topocolumn((rel: (1, 0), to: <h2>), 3)
      edge(<c2>, "-")
      edge(<c4>, "-")

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

#slide(steps:3)[
  == Formalizando o Problema

  Rota definida Pie é uma sequência de nós definido pelo nó de origem.
  
  #show: pause
  Rota realizada Pj é a sequência de nós que o pacote realmente percorreu.

  #show: pause

  Precisamos simplesmente detectar se
  #set align(center)
  $$ Pie = Pj $$
]

#slide(steps: 2)[
  == Solução proposta

  O pathsec propõe um método de verificação de rotas baseado em amostragem, onde o nó de origem define um pacote de amostragem (probe) e uma semente (timestamp), e os nós núcleos devem assinar um campo lhash@pathsec.

  #show: pause

  Isso define um modelo de multiassinatura. O controlador, que conhece os segredos dos núceos (nodeid) pode verificar se o pacote de amostragem foi assinado por todos os nós da rota, garantindo que o pacote seguiu a rota definida pelo nó de origem.
]

#slide[
  #bytefield(
    bpr: 64,
    // Config the header
    bitheader(
      "bytes",
      angle: -30deg, // angle (default: -60deg)
      // text-size: 8pt, // length (default: global header_font_size or 9pt)
    ),

    // Add data fields (bit, bits, byte, bytes) and notes
    // A note always aligns on the same row as the start of the next data field.
    // note(right)[#text(16pt, fill: blue, "Testing")],
    bytes(6, fill: red.lighten(30%))[`eth.dst`],
    bytes(6, fill: red.lighten(30%))[`eth.src`],
    bytes(2, fill: red.lighten(30%))[`eth.type`],

    bytes(1, fill: green.lighten(30%))[`plk.version`],
    bytes(1, fill: green.lighten(30%))[`plk.ttl`],
    bytes(2, fill: green.lighten(30%))[`plk.proto`],
    bits(160, fill: green.lighten(30%))[`plk.routeid`],
    bytes(4, fill: green.lighten(30%))[`prb.timestamp`],
    bytes(4, fill: green.lighten(30%))[`prb.l_hash`],

    bytes(2, fill: red.lighten(30%))[`ipv4`],
  )
]

#slide[
  #bibliography("../TCC2/bilbiography.bib")
]


// == Base topology
// #diagram({
//   topo(10)
//   host_node(
//     (rel: (-1, 0), to: <h1>),
//     nodetext($h_(11)$),
//     name: <h11>,
//   )
//   edge(<h11>, "-", <e1>)
// })
