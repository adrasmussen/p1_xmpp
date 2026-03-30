%%%-------------------------------------------------------------------
%%% @author Alex Rasmussen
%%% @copyright (C) 2026, Alex Rasmussen
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%%-------------------------------------------------------------------

-module(xmpp_sasl_gssapi).
-behaviour(xmpp_sasl).
-author('alex@nonlocal.cloud').

% TODO -- pick location for keytab/use kerlberos to get from local env
%         better error handling for missing keytab/log lines for mech
%% API
-export([mech_new/7, mech_step/2, format_error/1]).

-record(state, {
    lserver :: binary(),
    keytab :: krb_mit_keytab:keytab(),
    context :: gss_krb5:state() | none,
    gss_done :: boolean()
}).

-type error_reason() ::
    unknown_gss
    | sasl_wrap
    | sasl_unwrap
    | sasl_unsupported_layer
    | {atom(), binary()}.
-export_type([error_reason/0]).

-spec format_error(error_reason()) -> {atom(), binary()}.
format_error({gss, String}) ->
    {'not-authorized', <<"GSSAPI error: ", String>>};
format_error({bad_principal, String}) ->
    {'not-authorized', <<"Invalid user principal: ", String>>};
format_error({bad_realm, String}) ->
    {'not-authorized', <<"Invalid user realm: ", String>>};
format_error(unknown_gss) ->
    {'not-authorized', <<"Unknown GSSAPI error">>};
format_error(sasl_wrap) ->
    {'not-authorized', <<"Failed to encrypt SASL layer request">>};
format_error(sasl_unwrap) ->
    {'not-authorized', <<"Failed to decrypt client SASL layer response">>};
format_error(sasl_unsupported_layer) ->
    {'not-authorized', <<"Client requested invalid SASL layer">>}.

mech_new(_Mech, _CB, _PD, _Mechs, _UAId, Host, _Callbacks) ->
    % this function cannot fail, so just explode if
    % we can't read our keytab data
    {ok, KeyTab} = krb_mit_keytab:file("/etc/krb5.keytab"),

    #state{lserver = Host, keytab = KeyTab, context = none, gss_done = false}.

mech_step(State, ClientIn) ->
    handle_auth(ClientIn, State).

%
% gssapi sasl mechanism (rfc 4752)
%

% first response after client recieves GSS_S_COMPLETE and
% returns an empty token to begin the layer negotiation
handle_auth(<<>>, #state{context = Ctx, gss_done = true} = State) ->
    % advertise no security (1:8), but the rfc demands
    % that is this be sent to the client encrypted
    LayerMsg = <<7, 1, 0, 0>>,

    case gss_krb5:wrap(LayerMsg, Ctx) of
        {ok, TokenOut} ->
            {continue, TokenOut, State};
        {error, _} ->
            {error, sasl_wrap}
    end;
% this is the final mech_step(), and just verifies that the
% client doesn't think we're using gssapi encryption
handle_auth(TokenIn, #state{lserver = Lserver, context = Ctx, gss_done = true} = _State) ->
    case gss_krb5:unwrap(TokenIn, Ctx) of
        {ok, <<ChosenLayer:8, _ClientMaxBuf:24>>} ->
            case ChosenLayer of
                1 -> handle_name(Ctx, Lserver);
                _ -> {error, sasl_unsupported_layer}
            end;
        {error, _} ->
            {error, sasl_unwrap}
    end;
% set up the gss context and generate the first token
handle_auth(TokenIn, #state{keytab = KeyTab, context = none} = State) ->
    % while gssapi does support channel bindings, xmpp doesn't
    % appear to have a way to negotiate which binding before
    % the client passes the first token, and in any case the
    % kerberos tokens are already encrypted
    Opts = #{keytab => KeyTab, chan_bindings => <<0:128>>},

    handle_gss_result(gss_krb5:accept(TokenIn, Opts), State);
% most gssapi implementations should only need to do one step
% (i.e. decrypt the AP_REQ) but we want to be exhaustive
handle_auth(TokenIn, #state{context = Ctx} = State) ->
    handle_gss_result(gss_krb5:continue(TokenIn, Ctx), State).

handle_gss_result(Result, State) ->
    case Result of
        {continue, TokenOut, NewCtx} ->
            {continue, TokenOut, State#state{context = NewCtx, gss_done = false}};
        {ok, TokenOut, NewCtx} ->
            {continue, TokenOut, State#state{
                context = NewCtx,
                gss_done = true
            }};
        {ok, NewCtx} ->
            {continue, <<>>, State#state{
                context = NewCtx,
                gss_done = true
            }};
        {error, Reason} when is_atom(Reason) ->
            {error, {gss, atom_to_list(Reason)}};
        {error, _Reason} ->
            {error, unknown_gss}
    end.

% in principle (heh) we could allow the username and authzid to
% differ, but it doesn't make sense for gssapi
handle_name(Ctx, Lserver) ->
    Principal = gss_krb5:translate_name(gss_krb5:peer_name(Ctx)),
    case binary:split(Principal, <<$@>>) of
        [User, Domain] ->
            case jid:nameprep(Domain) of
                Lserver -> {ok, [{username, User}, {authzid, User}]};
                _ -> {error, {bad_realm, Domain}}
            end;
        _ ->
            {error, {bad_principal, Principal}}
    end.
