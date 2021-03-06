%%
%% %CopyrightBegin%
%% 
%% Copyright Ericsson AB 1996-2009. All Rights Reserved.
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
-module(init_SUITE).

-include("test_server.hrl").

-export([all/1]).

-export([get_arguments/1, get_argument/1, boot_var/1, restart/1,
	 get_plain_arguments/1,
	 reboot/1, stop/1, get_status/1, script_id/1, boot/1]).
-export([boot1/1, boot2/1]).

-export([init_per_testcase/2, fin_per_testcase/2]).

-export([init/1, fini/1]).

-define(DEFAULT_TIMEOUT_SEC, 100).

%%-----------------------------------------------------------------
%% Test suite for init. (Most code is run during system start/stop.
%% Should be started in a CC view with:
%% erl -sname master -rsh ctrsh
%%-----------------------------------------------------------------
all(suite) ->
    [get_arguments, get_argument, boot_var,
     get_plain_arguments,
     restart,
     get_status, script_id, boot].

init_per_testcase(Func, Config) when atom(Func), list(Config) ->
    Dog=?t:timetrap(?t:seconds(?DEFAULT_TIMEOUT_SEC)),
    [{watchdog, Dog}|Config].

fin_per_testcase(_Func, Config) ->
    Dog=?config(watchdog, Config),
    ?t:timetrap_cancel(Dog).

init(doc) -> [];
init(suite) -> [];
init(Config) when is_list(Config) ->
    Config.

fini(doc) -> [];
fini(suite) -> [];
fini(Config) when is_list(Config) ->
    Host = list_to_atom(from($@, atom_to_list(node()))),
    Node = list_to_atom(lists:concat([init_test, "@", Host])),
    stop_node(Node),
    Config.

get_arguments(doc) ->[];
get_arguments(suite) -> {req, [distribution, {local_slave_nodes, 1}]};
get_arguments(Config) when is_list(Config) ->
    ?line Dog = ?t:timetrap(?t:seconds(10)),

    Args = args(),
    ?line {ok, Node} = start_node(init_test, Args),
    ?line case rpc:call(Node, init, get_arguments, []) of
	      Arguments when is_list(Arguments) ->
		  stop_node(Node),
		  check_a(Arguments),
		  check_b(Arguments),
		  check_c(Arguments),
		  check_d(Arguments);
	      _ ->
		  stop_node(Node),
		  ?t:fail(get_arguments)
	  end,
    ?line ?t:timetrap_cancel(Dog),
    ok.

check_a(Args) ->
    case lists:keysearch(a,1,Args) of
	{value, {a,["kalle"]}} ->
	    Args1 = lists:keydelete(a,1,Args),
	    case lists:keysearch(a,1,Args1) of
		false ->
		    ok;
		_ ->
		    ?t:fail(check_a1)
	    end;
	_ ->
	    ?t:fail(check_a2)
    end.

check_b(Args) ->
    case lists:keysearch(b,1,Args) of
	{value, {b,["hej", "hopp"]}} ->
	    Args1 = lists:keydelete(b,1,Args),
	    case lists:keysearch(b,1,Args1) of
		{value, {b,["san", "sa"]}} ->
		    Args2 = lists:keydelete(b,1,Args1),
		    case lists:keysearch(b,1,Args2) of
			false ->
			    ok;
			_ ->
			    ?t:fail(check_b1)
		    end;
		_ ->
		    ?t:fail(check_b2)
	    end;
	_ ->
	    ?t:fail(check_b3)
    end.

check_c(Args) ->
    case lists:keysearch(c,1,Args) of
	{value, {c,["4", "5", "6"]}} ->
	    Args1 = lists:keydelete(c,1,Args),
	    case lists:keysearch(c,1,Args1) of
		{value, {c,["7", "8", "9"]}} ->
		    Args2 = lists:keydelete(c,1,Args1),
		    case lists:keysearch(c,1,Args2) of
			false ->
			    ok;
			_ ->
			    ?t:fail(check_c1)
		    end;
		_ ->
		    ?t:fail(check_c2)
	    end;
	_ ->
	    ?t:fail(check_c3)
    end.

check_d(Args) ->
    case lists:keysearch(d,1,Args) of
	{value, {d,[]}} ->
	    Args1 = lists:keydelete(d,1,Args),
	    case lists:keysearch(d,1,Args1) of
		false ->
		    ok;
		_ ->
		    ?t:fail(check_d1)
	    end;
	_ ->
	    ?t:fail(check_d2)
    end.

get_argument(doc) ->[];
get_argument(suite) -> {req, [distribution, {local_slave_nodes, 1}]};
get_argument(Config) when is_list(Config) ->
    ?line Dog = ?t:timetrap(?t:seconds(10)),

    Args = args(),
    ?line {ok, Node} = start_node(init_test, Args),
    ?line case rpc:call(Node, init, get_argument, [b]) of
	      {ok, [["hej", "hopp"],["san", "sa"]]} ->
		  ok;
	      _ ->
		  stop_node(Node),
		  ?t:fail({get_argument, b})
	  end,
    ?line case rpc:call(Node, init, get_argument, [a]) of
	      {ok, [["kalle"]]} ->
		  ok;
	      _ ->
		  stop_node(Node),
		  ?t:fail({get_argument, a})
	  end,
    ?line case rpc:call(Node, init, get_argument, [c]) of
	      {ok, [["4", "5", "6"], ["7", "8", "9"]]} ->
		  ok;
	      _ ->
		  stop_node(Node),
		  ?t:fail({get_argument, c})
	  end,
    ?line case rpc:call(Node, init, get_argument, [d]) of
	      {ok, [[]]} ->
		  ok;
	      _ ->
		  stop_node(Node),
		  ?t:fail({get_argument, d})
	  end,
    ?line case rpc:call(Node, init, get_argument, [e]) of
	      error ->
		  ok;
	      _ ->
		  stop_node(Node),
		  ?t:fail({get_argument, e})
	  end,
    stop_node(Node),
    ?line ?t:timetrap_cancel(Dog),
    ok.

get_plain_arguments(doc) ->[];
get_plain_arguments(suite) -> {req, [distribution, {local_slave_nodes, 1}]};
get_plain_arguments(Config) when is_list(Config) ->
    ?line Dog = ?t:timetrap(?t:seconds(10)),
    Longstring = 
	"fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2"
	"fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2"
	"fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2"
	"fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2"
	"fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2"
	"fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2"
	"fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2"
	"fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2"
	"fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2fjdkfjdkfjfdaa2",
    ?line true = (length(Longstring) > 255),
    Args = long_args(Longstring),
    ?line {ok, Node} = start_node(init_test, Args),
    ?line case rpc:call(Node, init, get_plain_arguments, []) of
	      ["a", "b", "c", Longstring] ->
		  ok;
	      As ->
		  stop_node(Node),
		  ?t:fail({get_argument, As})
	  end,
    stop_node(Node),
    ?line ?t:timetrap_cancel(Dog),

    ok.


%% ------------------------------------------------
%% Use -boot_var flag to set $TEST_VAR in boot script.
%% ------------------------------------------------
boot_var(doc) -> [];
boot_var(suite) -> {req, [distribution, {local_slave_nodes, 1}]};
boot_var(Config) when is_list(Config) ->
    case os:type() of
	vxworks ->
	    {comment, "Not run on VxWorks"};
	_ ->
	    ?line Dog = ?t:timetrap(?t:seconds(100)),
	    
	    {BootScript, TEST_VAR, KernelVsn, StdlibVsn} = create_boot(Config),

	    %% Should fail as we have not given -boot_var TEST_VAR
	    ?line {error, timeout} =
		start_node(init_test, "-boot " ++ BootScript),
	    
	    case is_real_system(KernelVsn, StdlibVsn) of
		true ->
		    %% Now it should work !!
		    ?line {ok, Node} =
			start_node(init_test,
				   "-boot " ++ BootScript ++
				   " -boot_var TEST_VAR " ++ TEST_VAR),
		    stop_node(Node),
		    Res = ok;
		_ ->
%% What we need is not so much version numbers on the directories, but
%% for the boot var TEST_VAR to appear in the boot script, and it doesn't
%% if we give the 'local' option to systools:make_script.
		    ?t:format(
		       "Test case not complete as we are not~n"
		       "running in a real system!~n"
		       "Probably this test is performed in a "
		       "clearcase view or source tree.~n"
		       "Need version numbers on the kernel and "
		       "stdlib directories!~n",
		       []),
		    Res = {skip,
			   "Test case only partially run since it is run "
			   "in a clearcase view or in a source tree. "
			   "Need an installed system to complete this test."}
	    end,
	    ?line ?t:timetrap_cancel(Dog),
	    Res
    end.

create_boot(Config) ->
    ?line {ok, OldDir} = file:get_cwd(),
    ?line {LatestDir, LatestName, KernelVsn, StdlibVsn} =
	create_script(Config),
    LibDir = code:lib_dir(),
    ?line ok = file:set_cwd(LatestDir),
    ?line ok = systools:make_script(LatestName,
				    [{variables, [{"TEST_VAR", LibDir}]}]),
    ?line ok = file:set_cwd(OldDir),
    {LatestDir ++ "/" ++ LatestName, LibDir, KernelVsn, StdlibVsn}.

is_real_system(KernelVsn, StdlibVsn) ->
    LibDir = code:lib_dir(),
    filelib:is_dir(filename:join(LibDir, "kernel"++KernelVsn)) andalso
	filelib:is_dir(filename:join(LibDir, "stdlib"++StdlibVsn)).
    
%% ------------------------------------------------
%% Slave executes erlang:halt() on master nodedown.
%% Therefore the slave process must be killed
%% before restart.
%% ------------------------------------------------
restart(doc) -> [];
restart(suite) ->
    case ?t:os_type() of
	{Fam, _} when Fam == unix; Fam == win32 ->
	    {req, [distribution, {local_slave_nodes, 1}, {time, 5}]};
	_ ->
	    {skip, "Only run on unix and win32"}
    end;
restart(Config) when is_list(Config) ->
    ?line Dog = ?t:timetrap(?t:seconds(40)),
    ?line Args = args(),

    %% Currently test_server:start_node cannot be used. The restarted
    %% node immediately halts due to the implementation of
    %% test_server:start_node.
    ?line {ok, Node} = loose_node:start(init_test, Args, ?DEFAULT_TIMEOUT_SEC),
    %% Ok, the node is up, now the real test test begins.
    ?line erlang:monitor_node(Node, true),
    ?line InitPid = rpc:call(Node, erlang, whereis, [init]),
    ?line Procs = rpc:call(Node, erlang, processes, []),
    ?line MaxPid = lists:last(Procs),
    ?line ok = rpc:call(Node, init, restart, []),
    ?line receive
	      {nodedown, Node} ->
		  ok
	  after 10000 ->
		  loose_node:stop(Node),
		  ?t:fail(not_stopping)
	  end,
    ?line ok = wait_restart(30, Node),

    %% Still the same init process!
    ?line InitPid1 = rpc:call(Node, erlang, whereis, [init]),
    InitP = pid_to_list(InitPid),
    ?line InitP = pid_to_list(InitPid1),

    ?line NewProcs0 = rpc:call(Node, erlang, processes, []),
    NewProcs = lists:delete(InitPid1, NewProcs0),
    ?line case check_processes(NewProcs, MaxPid) of
	      true ->
		  ok;
	      _ ->
		  loose_node:stop(Node),
		  ?t:fail(processes_not_greater)
	  end,

    %% Test that, for instance, the same argument still exists.
    ?line case rpc:call(Node, init, get_argument, [c]) of
	      {ok, [["4", "5", "6"], ["7", "8", "9"]]} ->
		  ok;
	      _ ->
		  loose_node:stop(Node),
		  ?t:fail({get_argument, restart_fail})
	  end,
    loose_node:stop(Node),
    ?line ?t:timetrap_cancel(Dog),
    ok.

wait_restart(0, _Node) ->
    ?t:fail(not_restarted);
wait_restart(N, Node) ->
    case net_adm:ping(Node) of
	pong -> ok;
	_ -> 
	    ?t:sleep(1000),
	    wait_restart(N - 1, Node)
    end.

check_processes(NewProcs, MaxPid) ->
    [N,P,I] = apid(MaxPid),
    case lists:filter(fun(Pid) ->
			      case apid(Pid) of
				  [N,P1,_I1] when P1 > P -> false;
				  [N,_P1,I1] when I1 > I -> false;
				  _                      -> true
			      end
		      end, NewProcs) of
	[] ->
	    true;
	_  ->
	    false
    end.

apid(Pid) ->
    [N,P,I] = string:tokens(pid_to_list(Pid),"<>."),
    [list_to_integer(N),list_to_integer(P),list_to_integer(I)].

%% ------------------------------------------------
%% Just test that the system is halted here.
%% The reboot facility using heart is tested
%% in the heart_SUITE.
%% ------------------------------------------------
reboot(doc) -> [];
reboot(suite) -> {req, [distribution, {local_slave_nodes, 1}]};
reboot(Config) when is_list(Config) ->
    ?line Dog = ?t:timetrap(?t:seconds(40)),

    Args = args(),
    ?line {ok, Node} = start_node(init_test, Args),
    erlang:monitor_node(Node, true),
    ?line ok = rpc:call(Node, init, reboot, []),
    ?line receive
	      {nodedown, Node} ->
		  ok
	  after 10000 ->
		  stop_node(Node),
		  ?t:fail(not_stopping)
	  end,
    ?t:sleep(5000),
    ?line case net_adm:ping(Node) of
	      pang ->
		  ok;
	      _ ->
		  stop_node(Node),
		  ?t:fail(system_rebooted)
	  end,
    ?line ?t:timetrap_cancel(Dog),
    ok.

%% ------------------------------------------------
%%
%% ------------------------------------------------
stop(doc) -> [];
stop(suite) -> [];
stop(Config) when is_list(Config) ->
    ?line Dog = ?t:timetrap(?t:seconds(20)),
    Args = args(),
    ?line {ok, Node} = start_node(init_test, Args),
    erlang:monitor_node(Node, true),
    ?line ok = rpc:call(Node, init, reboot, []),
    ?line receive
	      {nodedown, Node} ->
		  ok
	  after 10000 ->
		  stop_node(Node),
		  ?t:fail(not_stopping)
	  end,
    ?t:sleep(5000),
    ?line case net_adm:ping(Node) of
	      pang ->
		  ok;
	      _ ->
		  stop_node(Node),
		  ?t:fail(system_rebooted)
	  end,
    ?line ?t:timetrap_cancel(Dog),
    ok.

%% ------------------------------------------------
%% 
%% ------------------------------------------------
get_status(doc) -> [];
get_status(suite) -> [];
get_status(Config) when is_list(Config) ->
    ?line Dog = ?t:timetrap(?t:seconds(10)),
    ?line ?t:timetrap_cancel(Dog),

    ?line {Start, _} = init:get_status(),
    %% Depending on how the test_server is started Start has
    %% different values. staring if test_server started with
    %% -s flag.
    ?line case lists:member(Start, [started, starting]) of
	      true ->
		  ok;
	      _ ->
		  ?t:fail(get_status)
	  end.

%% ------------------------------------------------
%% 
%% ------------------------------------------------
script_id(doc) -> [];
script_id(suite) -> [];
script_id(Config) when is_list(Config) ->
    ?line Dog = ?t:timetrap(?t:seconds(10)),

    ?line {Name, Vsn} = init:script_id(),
    ?line if
	      list(Name), list(Vsn) ->
		  ok;
	      true ->
		  ?t:fail(not_standard_script)
	  end,
    ?line ?t:timetrap_cancel(Dog),
    ok.

%% ------------------------------------------------
%% Start the slave system with -boot flag.
%% ------------------------------------------------
boot(suite) -> [boot1, boot2].

boot1(doc) -> [];
boot1(suite) -> {req, [distribution, {local_slave_nodes, 1}, {time, 35}]};
boot1(Config) when is_list(Config) ->
    case os:type() of 
	vxworks ->
	    {comment, "Not run on VxWorks"};
	_ ->
	    ?line Dog = ?t:timetrap(?t:seconds(80)),
	    Args = args() ++ " -boot start_sasl",
	    ?line {ok, Node} = start_node(init_test, Args),
	    ?line stop_node(Node),

	    %% Try to start with non existing boot file.
	    Args1 = args() ++ " -boot dummy_script",
	    ?line {error, timeout} = start_node(init_test, Args1),
	    
	    ?line ?t:timetrap_cancel(Dog),
	    ok
    end.

boot2(doc) -> [];
boot2(suite) -> {req, [distribution, {local_slave_nodes, 1}, {time, 35}]};
boot2(Config) when is_list(Config) ->
    case os:type() of 
	vxworks ->
	    {comment, "Not run on VxWorks"};
	_ ->
	    ?line Dog = ?t:timetrap(?t:seconds(80)),

	    %% Absolute boot file name
	    Boot = filename:join([code:root_dir(), "bin", "start_sasl"]),

	    Args = args() ++ " -boot " ++ Boot,
	    ?line {ok, Node} = start_node(init_test, Args),
	    ?line stop_node(Node),

	    case os:type() of 
		{win32, _} ->
		    %% Absolute boot file name for Windows -- all slashes are
		    %% converted to backslashes.
		    Win_boot = lists:map(fun($/) -> $\\; (C) -> C end,
					 Boot),
		    Args2 = args() ++ " -boot " ++ Win_boot,
		    ?line {ok, Node2} = start_node(init_test, Args2),
		    ?line stop_node(Node2);
		_ ->
		    ok
	    end,

	    ?line ?t:timetrap_cancel(Dog),
	    ok
    end.

%% Misc. functions    

start_node(Name, Param) ->
    ?t:start_node(Name, slave, [{args, Param}]).

stop_node(Node) ->
    ?t:stop_node(Node).

from(H, [H | T]) -> T;
from(H, [_ | T]) -> from(H, T);
from(_, []) -> [].

args() ->
    "-a kalle -- a b -d -b hej hopp -- c d -b san sa -c 4 5 6 -c 7 8 9".

long_args(A) ->
    lists:flatten(
      io_lib:format("-a kalle -- a b -d -b hej hopp -- c "
		    "~s -b san sa -c 4 5 6 -c 7 8 9",
		    [A])).

create_script(Config) ->
    ?line PrivDir = ?config(priv_dir,Config),
    ?line Name = PrivDir ++ "boot_var_test",
    ?line Apps = application_controller:which_applications(),
    ?line {value,{_,_,KernelVer}} = lists:keysearch(kernel,1,Apps),
    ?line {value,{_,_,StdlibVer}} = lists:keysearch(stdlib,1,Apps),
    ?line {ok,Fd} = file:open(Name ++ ".rel", write),
    ?line io:format(Fd,
		    "{release, {\"Test release 3\", \"P2A\"}, \n"
		    " {erts, \"4.4\"}, \n"
		    " [{kernel, \"~s\"}, {stdlib, \"~s\"}]}.\n",
		    [KernelVer,StdlibVer]),
    ?line file:close(Fd),
    {filename:dirname(Name), filename:basename(Name),
    KernelVer, StdlibVer}.

