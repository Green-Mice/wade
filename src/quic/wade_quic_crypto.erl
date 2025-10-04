%% @doc QUIC cryptography and TLS 1.3 handshake.
%% Implements key derivation, AEAD encryption, and TLS 1.3 integration using Keylara.
-module(wade_quic_crypto).
-include("wade_quic.hrl").

%% Public API
-export([
    init_server/2,
    process_handshake/3,
    build_server_hello/1,
    is_complete/1,
    derive_initial_secrets/2,
    protect_packet/3,
    unprotect_packet/3
]).

%% TLS 1.3 constants
-define(TLS_AES_128_GCM_SHA256, 16#1301).
-define(TLS_CHACHA20_POLY1305_SHA256, 16#1303).

%% QUIC-specific labels for key derivation
-define(LABEL_CLIENT_IN, <<"client in">>).
-define(LABEL_SERVER_IN, <<"server in">>).
-define(LABEL_QUIC_KEY, <<"quic key">>).
-define(LABEL_QUIC_IV, <<"quic iv">>).
-define(LABEL_QUIC_HP, <<"quic hp">>).

%%=============================================================================
%% Public API
%%=============================================================================

%% @doc Initialize crypto state for server.
%% @param _LocalCID Local Connection ID (unused for now).
%% @param RemoteCID Remote Connection ID.
-spec init_server(binary(), binary()) -> map().
init_server(_LocalCID, RemoteCID) ->
    %% Derive initial secrets from destination connection ID
    InitialSalt = <<16#38, 16#76, 16#2c, 16#f7, 16#f5, 16#59, 16#34, 16#b3,
                    16#4d, 16#17, 16#9a, 16#e6, 16#a4, 16#c8, 16#0c, 16#ad,
                    16#cc, 16#bb, 16#7f, 16#0a>>,
    InitialSecret = hkdf_extract(InitialSalt, RemoteCID),
    ClientInitialSecret = hkdf_expand_label(InitialSecret, ?LABEL_CLIENT_IN, <<>>, 32),
    ServerInitialSecret = hkdf_expand_label(InitialSecret, ?LABEL_SERVER_IN, <<>>, 32),
    %% Derive keys for Initial packet protection
    InitialKeys = #{
        client => derive_packet_protection_keys(ClientInitialSecret),
        server => derive_packet_protection_keys(ServerInitialSecret)
    },
    #{
        initial => InitialKeys,
        handshake => undefined,
        application => undefined,
        handshake_complete => false,
        tls_state => init_tls_state()
    }.

%% @doc Process TLS handshake messages.
-spec process_handshake(binary(), atom(), map()) ->
    {ok, map(), binary()} | {error, term()}.
process_handshake(Data, Level, CryptoState) ->
    %% Parse TLS handshake messages
    case parse_tls_handshake(Data) of
        {ok, Messages} ->
            %% Process each message
            {NewTLSState, ResponseData} = process_tls_messages(
                Messages,
                Level,
                maps:get(tls_state, CryptoState)
            ),
            NewCryptoState = CryptoState#{tls_state => NewTLSState},
            %% Check if we should derive new keys
            FinalCryptoState = maybe_derive_keys(Level, NewCryptoState),
            {ok, FinalCryptoState, ResponseData};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Build server hello message.
-spec build_server_hello(map()) -> binary().
build_server_hello(CryptoState) ->
    TLSState = maps:get(tls_state, CryptoState),
    %% Build minimal TLS 1.3 ServerHello
    ServerRandom = crypto:strong_rand_bytes(32),
    CipherSuite = <<?TLS_AES_128_GCM_SHA256:16>>,
    %% Build extensions (minimal)
    SupportedVersionsExt = <<16#002b:16, 16#0002:16, 16#0304:16>>,  % TLS 1.3
    KeyShareExt = build_key_share_extension(TLSState),
    Extensions = <<SupportedVersionsExt/binary, KeyShareExt/binary>>,
    ExtensionsLen = byte_size(Extensions),
    ServerHello = <<
        16#02,                        % Handshake type: ServerHello
        0:8, 0:8, 70:8,              % Length (placeholder)
        16#0303:16,                   % Legacy version (TLS 1.2)
        ServerRandom:32/binary,
        0:8,                          % Session ID length
        CipherSuite/binary,
        0:8,                          % Compression method: none
        ExtensionsLen:16,
        Extensions/binary
    >>,
    %% Wrap in TLS record
    RecordType = 16#16,  % Handshake
    RecordVersion = 16#0301,  % TLS 1.0 for compatibility
    RecordLength = byte_size(ServerHello),
    <<RecordType:8, RecordVersion:16, RecordLength:16, ServerHello/binary>>.

%% @doc Check if handshake is complete.
-spec is_complete(map()) -> boolean().
is_complete(CryptoState) ->
    maps:get(handshake_complete, CryptoState, false).

%% @doc Derive initial secrets (QUIC v1 specific).
-spec derive_initial_secrets(binary(), client | server) -> map().
derive_initial_secrets(ConnectionID, Role) ->
    InitialSalt = <<16#38, 16#76, 16#2c, 16#f7, 16#f5, 16#59, 16#34, 16#b3,
                    16#4d, 16#17, 16#9a, 16#e6, 16#a4, 16#c8, 16#0c, 16#ad,
                    16#cc, 16#bb, 16#7f, 16#0a>>,
    InitialSecret = hkdf_extract(InitialSalt, ConnectionID),
    Label = case Role of
        client -> ?LABEL_CLIENT_IN;
        server -> ?LABEL_SERVER_IN
    end,
    Secret = hkdf_expand_label(InitialSecret, Label, <<>>, 32),
    derive_packet_protection_keys(Secret).

%% @doc Protect QUIC packet with AEAD using Keylara.
-spec protect_packet(binary(), map(), integer()) -> {ok, binary()} | {error, term()}.
protect_packet(Packet, Keys, PacketNumber) ->
    try
        %% Extract keys from the map
        KeyMap = maps:get(server, Keys, maps:get(client, Keys, #{})),
        Key = maps:get(key, KeyMap),
        IV = maps:get(iv, KeyMap),
        %% Header protection key is not used in this simplified version
        _HP = maps:get(header_key, KeyMap, <<>>),

        %% Construct nonce from IV and packet number
        Nonce = construct_nonce(IV, PacketNumber),

        %% Use Keylara AES for encryption
        {ok, EncryptedPayload} = keylara_aes:encrypt(Packet, Key, Nonce),

        %% Return the protected packet
        {ok, EncryptedPayload}
    catch
        error:Reason -> {error, Reason}
    end.

%% @doc Unprotect QUIC packet (decrypt AEAD) using Keylara.
-spec unprotect_packet(binary(), map(), integer()) ->
    {ok, binary(), integer()} | {error, term()}.
unprotect_packet(Packet, Keys, LargestPN) ->
    try
        %% Extract keys from the map
        KeyMap = maps:get(server, Keys, maps:get(client, Keys, #{})),
        Key = maps:get(key, KeyMap),
        IV = maps:get(iv, KeyMap),
        %% Header protection key is not used in this simplified version
        _HP = maps:get(header_key, KeyMap, <<>>),

        %% Construct nonce from IV and packet number
        Nonce = construct_nonce(IV, LargestPN),

        %% Use Keylara AES for decryption
        {ok, DecryptedPayload} = keylara_aes:decrypt(Packet, Key, Nonce),

        %% Return the unprotected packet
        {ok, DecryptedPayload, LargestPN}
    catch
        error:Reason -> {error, Reason}
    end.

%%=============================================================================
%% Internal Functions - Key Derivation
%%=============================================================================

%% @doc HKDF-Extract (RFC 5869).
hkdf_extract(Salt, IKM) ->
    crypto:mac(hmac, sha256, Salt, IKM).

%% @doc HKDF-Expand-Label (TLS 1.3 style).
hkdf_expand_label(Secret, Label, Context, Length) ->
    %% Build HkdfLabel structure
    QuicLabel = <<"tls13 ", Label/binary>>,
    LabelLen = byte_size(QuicLabel),
    ContextLen = byte_size(Context),
    HkdfLabel = <<
        Length:16,
        LabelLen:8,
        QuicLabel/binary,
        ContextLen:8,
        Context/binary
    >>,
    hkdf_expand(Secret, HkdfLabel, Length).

%% @doc HKDF-Expand (RFC 5869).
hkdf_expand(PRK, Info, Length) ->
    hkdf_expand(PRK, Info, Length, <<>>, 1, <<>>).

hkdf_expand(_PRK, _Info, Length, _Prev, _Counter, Acc) when byte_size(Acc) >= Length ->
    <<Result:Length/binary, _/binary>> = Acc,
    Result;
hkdf_expand(PRK, Info, Length, Prev, Counter, Acc) ->
    T = crypto:mac(hmac, sha256, PRK, <<Prev/binary, Info/binary, Counter:8>>),
    hkdf_expand(PRK, Info, Length, T, Counter + 1, <<Acc/binary, T/binary>>).

%% @doc Derive packet protection keys from secret.
derive_packet_protection_keys(Secret) ->
    Key = hkdf_expand_label(Secret, ?LABEL_QUIC_KEY, <<>>, 16),  % AES-128
    IV = hkdf_expand_label(Secret, ?LABEL_QUIC_IV, <<>>, 12),
    HP = hkdf_expand_label(Secret, ?LABEL_QUIC_HP, <<>>, 16),
    #{
        key => Key,
        iv => IV,
        header_key => HP
    }.

%% @doc Construct nonce for AEAD.
construct_nonce(IV, PacketNumber) ->
    %% XOR packet number with IV
    PNBytes = <<PacketNumber:64>>,
    IVSize = byte_size(IV),
    Padding = <<0:((IVSize - 8) * 8)>>,
    PNPadded = <<Padding/binary, PNBytes/binary>>,
    crypto:exor(IV, PNPadded).

%%=============================================================================
%% Internal Functions - TLS Processing
%%=============================================================================

%% @doc Initialize TLS state.
init_tls_state() ->
    #{
        client_random => undefined,
        server_random => crypto:strong_rand_bytes(32),
        cipher_suite => ?TLS_AES_128_GCM_SHA256,
        key_share => generate_key_pair(),
        handshake_messages => []
    }.

%% @doc Generate X25519 key pair.
generate_key_pair() ->
    {PublicKey, PrivateKey} = crypto:generate_key(ecdh, x25519),
    #{public => PublicKey, private => PrivateKey}.

%% @doc Parse TLS handshake messages.
parse_tls_handshake(Data) ->
    try
        parse_tls_records(Data, [])
    catch
        _:Err -> {error, Err}
    end.

parse_tls_records(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
parse_tls_records(<<Type:8, Length:24, Message:Length/binary, Rest/binary>>, Acc) ->
    ParsedMsg = #{type => Type, data => Message},
    parse_tls_records(Rest, [ParsedMsg | Acc]);
parse_tls_records(_, _) ->
    {error, invalid_handshake}.

%% @doc Process TLS messages.
process_tls_messages(Messages, Level, TLSState) ->
    lists:foldl(
        fun(Msg, {State, Response}) ->
            case process_tls_message(Msg, Level, State) of
                {NewState, NewResponse} ->
                    {NewState, <<Response/binary, NewResponse/binary>>};
                NewState ->
                    {NewState, Response}
            end
        end,
        {TLSState, <<>>},
        Messages
    ).

%% @doc Process individual TLS message.
process_tls_message(#{type := 16#01, data := Data}, initial, TLSState) ->
    %% ClientHello
    case parse_client_hello(Data) of
        {ok, ClientHello} ->
            %% Store client random and key share
            NewState = TLSState#{
                client_random => maps:get(random, ClientHello),
                client_key_share => maps:get(key_share, ClientHello, undefined)
            },
            {NewState, <<>>};
        {error, _} ->
            TLSState
    end;
process_tls_message(#{type := 16#0b}, handshake, TLSState) ->
    %% Certificate
    %% Just acknowledge receipt
    TLSState;
process_tls_message(#{type := 16#0f}, handshake, TLSState) ->
    %% CertificateVerify
    TLSState;
process_tls_message(#{type := 16#14}, handshake, TLSState) ->
    %% Finished
    %% Handshake complete!
    TLSState#{handshake_complete => true};
process_tls_message(_Msg, _Level, TLSState) ->
    TLSState.

%% @doc Parse ClientHello message.
parse_client_hello(Data) ->
    try
        <<_LegacyVersion:16, Random:32/binary, SessionIDLen:8,
          _SessionID:SessionIDLen/binary, Rest1/binary>> = Data,
        <<CipherSuitesLen:16, _CipherSuites:CipherSuitesLen/binary, Rest2/binary>> = Rest1,
        <<CompressionLen:8, _Compression:CompressionLen/binary, Rest3/binary>> = Rest2,
        <<ExtensionsLen:16, Extensions:ExtensionsLen/binary, _/binary>> = Rest3,
        %% Parse extensions to find key_share
        KeyShare = parse_extensions_for_key_share(Extensions),
        {ok, #{random => Random, key_share => KeyShare}}
    catch
        _:_ -> {error, invalid_client_hello}
    end.

%% @doc Parse extensions to extract key share.
parse_extensions_for_key_share(<<>>) ->
    undefined;
parse_extensions_for_key_share(<<Type:16, Length:16, Data:Length/binary, Rest/binary>>) ->
    case Type of
        16#0033 ->  % key_share extension
            %% Extract public key (simplified)
            case Data of
                <<_ListLen:16, _Group:16, KeyLen:16, Key:KeyLen/binary, _/binary>> ->
                    Key;
                _ ->
                    parse_extensions_for_key_share(Rest)
            end;
        _ ->
            parse_extensions_for_key_share(Rest)
    end;
parse_extensions_for_key_share(_) ->
    undefined.

%% @doc Build KeyShare extension for ServerHello.
build_key_share_extension(TLSState) ->
    KeyShare = maps:get(key_share, TLSState),
    PublicKey = maps:get(public, KeyShare),
    KeyLen = byte_size(PublicKey),
    %% Extension type: key_share (0x0033)
    %% Group: x25519 (0x001d)
    <<16#0033:16,                     % Extension type
      (4 + KeyLen):16,                % Extension length
      16#001d:16,                     % Group: x25519
      KeyLen:16,                      % Key length
      PublicKey/binary>>.

%% @doc Maybe derive new keys based on handshake progress.
maybe_derive_keys(handshake, CryptoState) ->
    %% Derive handshake keys from shared secret
    case maps:get(tls_state, CryptoState) of
        #{client_key_share := ClientPubKey, key_share := #{private := PrivKey}} = TLSState ->
            %% Compute shared secret
            SharedSecret = crypto:compute_key(ecdh, ClientPubKey, PrivKey, x25519),
            %% Derive handshake secrets
            EarlySecret = hkdf_extract(<<0:256>>, <<>>),
            EmptyHash = crypto:hash(sha256, <<>>),
            DerivedSecret = hkdf_expand_label(EarlySecret, <<"derived">>, EmptyHash, 32),
            HandshakeSecret = hkdf_extract(DerivedSecret, SharedSecret),
            ClientHSSecret = hkdf_expand_label(HandshakeSecret, <<"c hs traffic">>, <<>>, 32),
            ServerHSSecret = hkdf_expand_label(HandshakeSecret, <<"s hs traffic">>, <<>>, 32),
            HandshakeKeys = #{
                client => derive_packet_protection_keys(ClientHSSecret),
                server => derive_packet_protection_keys(ServerHSSecret)
            },
            CryptoState#{
                handshake => HandshakeKeys,
                tls_state => TLSState#{handshake_secret => HandshakeSecret}
            };
        _ ->
            CryptoState
    end;
maybe_derive_keys(application, CryptoState) ->
    %% Derive application keys
    case maps:get(tls_state, CryptoState) of
        #{handshake_secret := HandshakeSecret} = TLSState ->
            EmptyHash = crypto:hash(sha256, <<>>),
            DerivedSecret = hkdf_expand_label(HandshakeSecret, <<"derived">>, EmptyHash, 32),
            MasterSecret = hkdf_extract(DerivedSecret, <<0:256>>),
            ClientAppSecret = hkdf_expand_label(MasterSecret, <<"c ap traffic">>, <<>>, 32),
            ServerAppSecret = hkdf_expand_label(MasterSecret, <<"s ap traffic">>, <<>>, 32),
            ApplicationKeys = #{
                client => derive_packet_protection_keys(ClientAppSecret),
                server => derive_packet_protection_keys(ServerAppSecret)
            },
            CryptoState#{
                application => ApplicationKeys,
                tls_state => TLSState#{master_secret => MasterSecret}
            };
        _ ->
            CryptoState
    end;
maybe_derive_keys(_, CryptoState) ->
    CryptoState.

