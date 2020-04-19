-module(par2_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Procs = [#{id => par2,
	       start => {par2, start_link, []},
	       restart => permanent,
	       shutdown => brutal_kill,
	       type => worker,
	       modules => [par2]}],
    {ok, {{one_for_one, 1, 5}, Procs}}.
