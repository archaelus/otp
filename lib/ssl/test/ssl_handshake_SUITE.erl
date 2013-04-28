%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 2008-2013. All Rights Reserved.
%%
%% The contents of this file are subject to the Erlang Public License,
%% Version 1.1, (the "License"); you may not use this file except in
%% compliance with the License. You should have received a copy of the
%% Erlang Public License along with this software. If not, it can be
%% retrieved online at http://www.erlang.org/.
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and limitations
%% under the License.
%%
%% %CopyrightEnd%
%%

%%

-module(ssl_handshake_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include("ssl_internal.hrl").
-include("ssl_handshake.hrl").

%%--------------------------------------------------------------------
%% Common Test interface functions -----------------------------------
%%--------------------------------------------------------------------
suite() -> [{ct_hooks,[ts_install_cth]}].

all() -> [
	decode_hello_handshake,
	decode_single_hello_extension_correctly,
	decode_unknown_hello_extension_correctly,
	decode_sni_hello_extension_correctly,
	decode_sni_handshake
	].

%%--------------------------------------------------------------------
%% Test Cases --------------------------------------------------------
%%--------------------------------------------------------------------
decode_hello_handshake(_Config) ->
	HelloPacket = <<16#02, 16#00, 16#00,
	16#44, 16#03, 16#03, 16#4e, 16#7f, 16#c1, 16#03, 16#35,
	16#c2, 16#07, 16#b9, 16#4a, 16#58, 16#af, 16#34, 16#07,
	16#a6, 16#7e, 16#ef, 16#52, 16#cb, 16#e0, 16#ea, 16#b7,
	16#aa, 16#47, 16#c8, 16#c2, 16#2c, 16#66, 16#fa, 16#f8,
	16#09, 16#42, 16#cf, 16#00, 16#c0, 16#30, 16#00, 16#00,
	16#1c, 
	16#00, 16#0b, 16#00, 16#04, 16#03, 16#00, 16#01, 16#02, % ec_point_formats
	16#ff, 16#01, 16#00, 16#01, 16#00, %% renegotiate 
	16#00, 16#23,
	16#00, 16#00, 16#33, 16#74, 16#00, 16#07, 16#06, 16#73,
	16#70, 16#64, 16#79, 16#2f, 16#32>>,
	
	Version = {3, 0},
	{Records, _Buffer} = ssl_handshake:get_tls_handshake(Version, HelloPacket, <<>>),
	
	{Hello, _Data} = hd(Records),
	#renegotiation_info{renegotiated_connection = <<0>>} = Hello#server_hello.renegotiation_info.
	
decode_single_hello_extension_correctly(_Config) -> 
	Renegotiation = <<?UINT16(?RENEGOTIATION_EXT), ?UINT16(1), 0>>,
	Extensions = ssl_handshake:dec_hello_extensions(Renegotiation, []),
	[{renegotiation_info,#renegotiation_info{renegotiated_connection = <<0>>}}] = Extensions.
	

decode_unknown_hello_extension_correctly(_Config) ->
	FourByteUnknown = <<16#CA,16#FE, ?UINT16(4), 3, 0, 1, 2>>,
	Renegotiation = <<?UINT16(?RENEGOTIATION_EXT), ?UINT16(1), 0>>,
	Extensions = ssl_handshake:dec_hello_extensions(<<FourByteUnknown/binary, Renegotiation/binary>>, []),
	[{renegotiation_info,#renegotiation_info{renegotiated_connection = <<0>>}}] = Extensions.
	

decode_sni_hello_extension_correctly(_Config) ->
    SNIExt = <<0,0,0,20,0,18,0,0,15,102,111,
               111,46,101,120,97,109,112,108,101,46,99,111,109>>,
    Extensions = ssl_handshake:dec_hello_extensions(SNIExt, []),
    [{server_name_indication,
      #server_name_list{names =
                            [#server_name{hostname = <<"foo.example.com">>}]}}]
      = Extensions.

decode_sni_handshake(_Config) ->
    ClientHelloFragment = <<1,0,0,116,3,1,80,91,143,53,246,93,213,47,
                            185,134,173,151,94,190,51,167,196,21,234,
                            56,45,87,53,35,226,179,65,216,105,27,88,
                            204,0,0,46,0,57,0,56,0,53,0,22,0,19,0,10,0,
                            51,0,50,0,47,0,154,0,153,0,150,0,5,0,4,0,
                            21,0,18,0,9,0,20,0,17,0,8,0,6,0,3,0,255,2,
                            1,0,0,28,0,0,0,20,0,18,0,0,15,102,111,111,
                            46,101,120,97,109,112,108,101,46,99,111,
                            109,0,35,0,0>>,
    Version = {3, 1},
    {[{#client_hello{server_name_indication =
           #server_name_list{names =
               [#server_name{hostname = <<"foo.example.com">>} ]}},
       _}],
     _} = ssl_handshake:get_tls_handshake(Version, ClientHelloFragment, <<>>).
