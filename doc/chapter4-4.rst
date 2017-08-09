l3 module
~~~~~~~~~

モジュール構成図
^^^^^^^^^^^^^^^^

以下に、モジュール構成図を示す。

.. figure:: l3-module.png

モジュール機能一覧
^^^^^^^^^^^^^^^^^^^^^^

本モジュールは以下の機能を提供する。()内は実装言語を表す。

-  モジュールメイン処理（Go）

-  システム情報処理（Go）

-  パケット処理（C）

   -  route情報取得処理

   -  arp情報取得処理

   -  IPルーティングパケット転送用処理

以降は、各機能について詳細を記載する。

モジュールメイン処理
^^^^^^^^^^^^^^^^^^^^^^^^

本モジュールを構成するための基本処理を提供する。
初期化処理、終了処理およびメイン処理の呼び出しを行う。
基本処理に関しては、データプレーンメインフレームワークが提供するモジュール定義に従って実装する。

システム情報処理
^^^^^^^^^^^^^^^^^^^^^^^^

本モジュールにおいて外部設定が可能な情報は以下のとおりである。

-  vrf情報

-  route情報

-  arp情報

-  interface情報

route情報およびarp情報は、外部エージェントからControl APIを経由して設定される。Control APIでは、VRF ID毎のroute情報の追加・削除、arp情報の追加・削除を可能にする。各設定情報を整形し、パケット処理部にDPDK ringを利用して情報の受け渡しを行う。

以下に対応するControl()を記載する。

``VRF_CREATE``
  route情報管理テーブルおよびarp情報管理テーブルをVRF毎に作成する。
  引数はVRF ID(uint64)である。

``ROUTE_ADD``
  route情報管理テーブルにroute情報を登録する。
  引数はVRF ID(uint64) と ``l3.RouteEntry`` 型の構造体である。

``ROUTE_DELETE``
  route情報管理テーブルからroute情報を削除する。
  引数はVRF ID(uint64) と ``l3.RouteEntry`` 型の構造体である。

``ARP_ADD``
  arp情報管理テーブルにarp情報を登録する。
  引数はVRF ID(uint64) と ``l3.ArpEntry`` 型の構造体である。

``ARP_DELETE``
  arp情報管理テーブルからarp情報を削除する。
  引数はVRF ID(uint64) と ``l3.ArpEntry`` 型の構造体である。

``INTERFACE_ADD``
  interface情報管理テーブルにinterface情報を登録する。
  引数はVRF ID(uint64) と ``l3.InterfaceEntry`` 型の構造体である。

``INTERFACE_DELETE``
  interface情報管理テーブルからinterface情報を削除する。
  引数はVRF ID(uint64) と ``l3.InterfaceEntry`` 型の構造体である。

パケット処理
^^^^^^^^^^^^^^^^^^^^^^^^

パケット処理部は既存処理を流用して以下の処理を行うが、本開発では新規に以下の2つのテーブルを保持・管理する。

-  VRF管理情報テーブル

  VRF毎にroute情報およびarp情報を管理するため、VRF情報管理テーブルを保持する。
  VRF情報管理テーブルはVRF IDをkeyとして、VRFに属するroute情報管理テーブルおよびarp情報管理テーブルを保持するテーブルである。

-  interface情報管理テーブル

  自ホストのインタフェース情報を管理するため、interface情報管理テーブルも保持する。interface情報管理テーブルは、VIF IDをkeyとして対応するMACアドレスを保持するテーブルである。

**route情報取得処理**

VRF IDに対応したroute情報管理テーブルから、パケット内の送信先IPアドレスに対応するroute情報を取得する。
取得したroute情報のnexthopから送信先IPアドレスを決定する。決定したIPアドレスはarp情報の取得に使用する。

**arp情報取得処理**

VRF IDに対応したarp情報管理テーブルから、パケット内の送信先IPアドレスに対応するarp情報を取得する。取得したarp情報から送信MACアドレスを決定する。

**IPルーティングパケット転送用処理**

route情報およびarp情報の取得により、転送先が決定した場合、転送処理用に必要なパケットヘッダの書き換え処理を行う。
IPヘッダにおいては、TTLおよびchecksumの再設定を行う。
Etherヘッダにおいては、送信先MACアドレスおよび送信元MACアドレスの書き換えを行う。
送信先MACアドレスはarp情報取得処理で取得したMACアドレスを使用する。
送信元MACアドレスはroute情報取得処理で取得したinterface indexからinterface情報テーブルからMACアドレスを取得したものを使用する。

本moduleは、これらの処理をおこなったパケットをdispatcherに渡すことにより、その後birdge module（詳細は bridge module の章を参照のこと）を経由した転送処理が行われること期待する。
