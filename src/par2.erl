-module(par2).

-behaviour(gen_server).

%% API
-export([start_link/0, start/0, stop/0]).
-export([create/1, create/2, repair/1, verify/1, get_md5/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3, format_status/2]).

-define(SERVER, ?MODULE).
-define(MAGIC, "PAR2\0PKT").
-define(FILEVERIFICATION, "PAR 2.0\0IFSC\0\0\0\0").
-define(FILEDESCRIPTION, "PAR 2.0\0FileDesc").
-define(RECOVERYBLOCK, "PAR 2.0\0RecvSlic").
-define(MAIN, "PAR 2.0\0Main\0\0\0\0").
-define(CREATOR, "PAR 2.0\0Creator\0").
-define(HEADER_SIZE, 64).

-record(state, {}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the application
%% @end
%%--------------------------------------------------------------------
start() ->
    application:start(par2).

%%--------------------------------------------------------------------
%% @doc
%% Starts the application
%% @end
%%--------------------------------------------------------------------
stop() ->
    application:stop(par2).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------
-spec start_link() -> {ok, Pid :: pid()} |
		      {error, Error :: {already_started, pid()}} |
		      {error, Error :: term()} |
		      ignore.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%--------------------------------------------------------------------
%% @doc
%% Create PAR2 files
%% Args is a list of strings and/or binaries arguments passed to the par2create cli
%% Refer to Par2's man for more info
%% @end
%%--------------------------------------------------------------------
-spec create(Args :: list()) -> ok | {error, Error :: string()}.
create(Args) ->
    gen_server:call(?SERVER, {create, Args}).

%%--------------------------------------------------------------------
%% @doc
%% Create PAR2 files with predefined options based on expected redundancy size <br/>
%% - ["-b100", "-r5", "-n1"] when smaller than 1280 KiB  <br/>
%% - ["-c10", "-s131072", "-n1"] when larger  <br/>
%% Trying to optimize for small redundancies, especially for KBs files
%% @end
%%--------------------------------------------------------------------
-spec create(Filename :: string(), Size :: integer()) -> ok | {error, Error :: string()}.
create(Filename, Size) ->
    gen_server:call(?SERVER, {create, Filename, Size}).

%%--------------------------------------------------------------------
%% @doc
%% Repair files using PAR2 files
%% @end
%%--------------------------------------------------------------------
-spec repair(Filename :: string()) -> ok | repaired | {error, Error :: string()}.
repair(Filename) ->
    gen_server:call(?SERVER, {repair, Filename}).

%%--------------------------------------------------------------------
%% @doc
%% Verify files using PAR2 files
%% @end
%%--------------------------------------------------------------------
-spec verify(Filename :: string()) -> ok | repaired | {error, Error :: string()}.
verify(Filename) ->
    gen_server:call(?SERVER, {repair, Filename}).

%%--------------------------------------------------------------------
%% @doc
%% Get the md5sum from the par2 file
%% @end
%%--------------------------------------------------------------------
get_md5(Filename) ->
    gen_server:call(?SERVER, {get_md5, Filename}).
    
%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%% @end
%%--------------------------------------------------------------------
-spec init(Args :: term()) -> {ok, State :: term()} |
			      {ok, State :: term(), Timeout :: timeout()} |
			      {ok, State :: term(), hibernate} |
			      {stop, Reason :: term()} |
			      ignore.
init([]) ->
    process_flag(trap_exit, true),
    {ok, #state{}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%% @end
%%--------------------------------------------------------------------
-spec handle_call(Request :: term(), From :: {pid(), term()}, State :: term()) ->
			 {reply, Reply :: term(), NewState :: term()} |
			 {reply, Reply :: term(), NewState :: term(), Timeout :: timeout()} |
			 {reply, Reply :: term(), NewState :: term(), hibernate} |
			 {noreply, NewState :: term()} |
			 {noreply, NewState :: term(), Timeout :: timeout()} |
			 {noreply, NewState :: term(), hibernate} |
			 {stop, Reason :: term(), Reply :: term(), NewState :: term()} |
			 {stop, Reason :: term(), NewState :: term()}.
handle_call({create, Filename, Size}, _From, State) ->
    Reply = do_create(Filename, Size),
    {reply, Reply, State};
handle_call({repair, Filename}, _From, State) ->
    Reply = do_repair(Filename),
    {reply, Reply, State};
handle_call({verify, Filename}, _From, State) ->
    Reply = do_verify(Filename),
    {reply, Reply, State};
handle_call({get_md5, Filename}, _From, State) ->
    Reply = do_get_md5(file:read_file(Filename)),
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%% @end
%%--------------------------------------------------------------------
-spec handle_cast(Request :: term(), State :: term()) ->
			 {noreply, NewState :: term()} |
			 {noreply, NewState :: term(), Timeout :: timeout()} |
			 {noreply, NewState :: term(), hibernate} |
			 {stop, Reason :: term(), NewState :: term()}.
handle_cast(_Request, State) ->
    {noreply, State}.
%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%% @end
%%--------------------------------------------------------------------
-spec handle_info(Info :: timeout() | term(), State :: term()) ->
			 {noreply, NewState :: term()} |
			 {noreply, NewState :: term(), Timeout :: timeout()} |
			 {noreply, NewState :: term(), hibernate} |
			 {stop, Reason :: normal | term(), NewState :: term()}.
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%% @end
%%--------------------------------------------------------------------
-spec terminate(Reason :: normal | shutdown | {shutdown, term()} | term(),
		State :: term()) -> any().
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%% @end
%%--------------------------------------------------------------------
-spec code_change(OldVsn :: term() | {down, term()},
		  State :: term(),
		  Extra :: term()) -> {ok, NewState :: term()} |
				      {error, Reason :: term()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called for changing the form and appearance
%% of gen_server status when it is returned from sys:get_status/1,2
%% or when it appears in termination error logs.
%% @end
%%--------------------------------------------------------------------
-spec format_status(Opt :: normal | terminate,
		    Status :: list()) -> Status :: term().
format_status(_Opt, Status) ->
    Status.

%%%===================================================================
%%% Internal functions
%%%===================================================================
do_create(Filename, Size) when Size/100*5 < 10 * 128 * 1024 ->
    do_create({args,["-q",
		     "-b100",
		     "-r5",
		     "-n1",
		     filename:flatten([Filename,".par2"]),
		     Filename]});
do_create(Filename, Size) when Size/100*5 < 10 * 128 * 1024 ->
    do_create({args,["-q",
		     "-c10",
		     "-s131072",
		     "-n1",
		     filename:flatten([Filename,".par2"]),
		     Filename]}).

do_create(Args) ->
    Port = open_port({spawn_executable, os:find_executable("par2create")},
		     [hide, stream, stderr_to_stdout,
		      stream, {line, 1000000},
		      {args,Args}]),
    collect_response(Port).

do_repair(Filename) ->
    Port = open_port({spawn_executable, os:find_executable("par2")},
		     [hide, stream, {line, 1000000}, stderr_to_stdout, {args,["repair", "-q", Filename]}]),
    collect_response(Port).

do_verify(Filename) ->
    Port = open_port({spawn_executable, os:find_executable("par2")},
		     [hide, stream, {line, 1000000}, stderr_to_stdout, {args,["verify", "-q", Filename]}]),
    collect_response(Port).

do_get_md5({error, _} = Err) ->
	    Err;
do_get_md5({ok, Data}) ->
    parse_par2(Data, <<?FILEDESCRIPTION>>, hashfull).

parse_par2(<<?MAGIC, 
	     Length:64/little, %% Length of entire packet including header
	     _Hash:16/binary, %% Hash of entire packet excepting the first 3 fields
	     _SetID:16/binary, %% Normally computed as the Hash of body of "Main Packet"
	     PacketType:16/binary, %% Used to specify the meaning of the rest of the packet
	     _Rest/binary>> = Par2,
	   PacketType,
	   Field) ->
    parse_packet(binary_part(Par2, 0, Length), PacketType, Field);


parse_par2(<<?MAGIC, 
	     Length:64/little, %% Length of entire packet including header
	     _Hash:16/binary, %% Hash of entire packet excepting the first 3 fields
	     _SetID:16/binary, %% Normally computed as the Hash of body of "Main Packet"
	     _AnotherPacketType:16/binary, %% Used to specify the meaning of the rest of the packet
	     _Rest/binary>> = Par2,
	   PacketType,
	   Field) ->
    parse_par2(binary_part(Par2, Length, size(Par2) - Length), PacketType, Field);

parse_par2(_, _, _) ->
    {error, enopar}.

parse_packet(<<_Header:64/binary,
	       FileID:16/binary,
	       HashFull:16/binary,
	       Hash16k:16/binary,
	       Length:64/little,
	       Name/binary>>,
	     <<?FILEDESCRIPTION>>,
	     Field) ->
    Packet = #{fileid => FileID, %% MD5hash of [hash16k, length, name]
	       hashfull => HashFull, %% MD5 Hash of the whole file
	       hash16k => Hash16k, %% MD5 Hash of the first 16k of the file
	       length => Length, %% Length of the file
	       name => Name},   %% Name of the file, padded with 1 to 3 zero bytes to reach 
				%% a multiple of 4 bytes.
				%% Actual length can be determined from overall packet
				%% length and then working backwards to find the first non
				%% zero character.
    maps:get(Field, Packet).




collect_response(Port) ->
    receive
        {Port,{data, {eol, "Done"}}} ->
            ok;
	
	{Port,{data, {eol, "All files are correct, repair is not required."}}} ->
            ok;
	
	{Port,{data, {eol, "Repair complete."}}} ->
            repaired;
	
	{Port,{data, {eol, "Repair is possible."}}} ->
	    repairable;

	{Port,{data, {eol, "Repair is not possible."}}} ->
	    unrepairable;

        {Port,{data, {eol, String}}} ->
	    case erlang:port_info(Port, connected) of
		undefined -> String;
		{connected, _Pid} -> collect_response(Port)
	    end
    %% %% Prevent the gen_server from hanging indefinitely in case the
    %% %% spawned process is taking too long processing the request.
    %% after 60*1000 -> 
    %%         {error, timeout}
    end.

%%%===================================================================
%%% EUNIT
%%%===================================================================
-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

do_create_test() ->
    [file:delete(X) || X <- filelib:wildcard("test/md5.gif.*")],
    ok = do_create([ "-q",
		     "-b100",
		     "-r1",
		     "-n1",
		     "test/md5.gif"]).

do_verify_test() ->
    Filename = "test/md5.gif.par2",
    ok = do_verify(Filename).

parse_par2_test() ->
    Filename = "test/md5.gif",
    {ok, Data} = file:read_file(Filename),
    {ok, Par2_Data} = file:read_file(Filename++".par2"),
    <<Data_MD5:16/binary>> = crypto:hash(md5, Data),
    <<Par2_Data_MD5:16/binary>> = parse_par2(Par2_Data, <<?FILEDESCRIPTION>>, hashfull),
    true = Data_MD5 == Par2_Data_MD5.

-endif.
