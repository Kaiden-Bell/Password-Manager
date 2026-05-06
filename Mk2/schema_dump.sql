--
-- PostgreSQL database dump
--

\restrict 7b6t4rtpFvpuD6Ak0qHl5aZIFd9ivLodQHrwYF53yQ8szuuTAAsFbTNDxzaGafu

-- Dumped from database version 16.13 (Ubuntu 16.13-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.13 (Ubuntu 16.13-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: access_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.access_logs (
    log_id integer NOT NULL,
    vault_id integer,
    user_id integer,
    event_type text NOT NULL,
    auth_method text,
    success integer NOT NULL,
    details text,
    created_at text NOT NULL
);


ALTER TABLE public.access_logs OWNER TO postgres;

--
-- Name: access_logs_log_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.access_logs_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.access_logs_log_id_seq OWNER TO postgres;

--
-- Name: access_logs_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.access_logs_log_id_seq OWNED BY public.access_logs.log_id;


--
-- Name: auth_credentials; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.auth_credentials (
    auth_id integer NOT NULL,
    vault_id integer NOT NULL,
    passphrase_salt text NOT NULL,
    wrapped_master_key text NOT NULL,
    wrapped_master_key_nonce text NOT NULL,
    kdf_name text DEFAULT 'argon2id'::text NOT NULL,
    kdf_memory_cost integer NOT NULL,
    kdf_time_cost integer NOT NULL,
    kdf_parallelism integer NOT NULL,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


ALTER TABLE public.auth_credentials OWNER TO postgres;

--
-- Name: auth_credentials_auth_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.auth_credentials_auth_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.auth_credentials_auth_id_seq OWNER TO postgres;

--
-- Name: auth_credentials_auth_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.auth_credentials_auth_id_seq OWNED BY public.auth_credentials.auth_id;


--
-- Name: hardware_auth; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.hardware_auth (
    hardware_auth_id integer NOT NULL,
    vault_id integer NOT NULL,
    keypad_pin_hash text NOT NULL,
    keypad_pin_salt text NOT NULL,
    enabled integer DEFAULT 1 NOT NULL,
    failed_attempts integer DEFAULT 0 NOT NULL,
    last_success_at text,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


ALTER TABLE public.hardware_auth OWNER TO postgres;

--
-- Name: hardware_auth_hardware_auth_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.hardware_auth_hardware_auth_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.hardware_auth_hardware_auth_id_seq OWNER TO postgres;

--
-- Name: hardware_auth_hardware_auth_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.hardware_auth_hardware_auth_id_seq OWNED BY public.hardware_auth.hardware_auth_id;


--
-- Name: hardware_devices; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.hardware_devices (
    device_id integer NOT NULL,
    vault_id integer NOT NULL,
    device_name text NOT NULL,
    device_type text NOT NULL,
    serial_port text,
    enabled integer DEFAULT 1 NOT NULL,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


ALTER TABLE public.hardware_devices OWNER TO postgres;

--
-- Name: hardware_devices_device_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.hardware_devices_device_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.hardware_devices_device_id_seq OWNER TO postgres;

--
-- Name: hardware_devices_device_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.hardware_devices_device_id_seq OWNED BY public.hardware_devices.device_id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    user_id integer NOT NULL,
    username text NOT NULL,
    display_name text NOT NULL,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


ALTER TABLE public.users OWNER TO postgres;

--
-- Name: users_user_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.users_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.users_user_id_seq OWNER TO postgres;

--
-- Name: users_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.users_user_id_seq OWNED BY public.users.user_id;


--
-- Name: vault_data; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.vault_data (
    data_id integer NOT NULL,
    vault_id integer NOT NULL,
    encrypted_blob text NOT NULL,
    nonce text NOT NULL,
    algorithm text DEFAULT 'xchacha20-poly1305'::text NOT NULL,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


ALTER TABLE public.vault_data OWNER TO postgres;

--
-- Name: vault_data_data_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.vault_data_data_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.vault_data_data_id_seq OWNER TO postgres;

--
-- Name: vault_data_data_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.vault_data_data_id_seq OWNED BY public.vault_data.data_id;


--
-- Name: vault_policy; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.vault_policy (
    policy_id integer NOT NULL,
    vault_id integer NOT NULL,
    hardware_gate_required integer DEFAULT 0 NOT NULL,
    software_only_enabled integer DEFAULT 1 NOT NULL,
    gate_window_seconds integer DEFAULT 60 NOT NULL,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


ALTER TABLE public.vault_policy OWNER TO postgres;

--
-- Name: vault_policy_policy_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.vault_policy_policy_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.vault_policy_policy_id_seq OWNER TO postgres;

--
-- Name: vault_policy_policy_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.vault_policy_policy_id_seq OWNED BY public.vault_policy.policy_id;


--
-- Name: vaults; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.vaults (
    vault_id integer NOT NULL,
    user_id integer NOT NULL,
    vault_name text NOT NULL,
    vault_status text DEFAULT 'LOCKED'::text NOT NULL,
    created_at text NOT NULL,
    updated_at text NOT NULL
);


ALTER TABLE public.vaults OWNER TO postgres;

--
-- Name: vaults_vault_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.vaults_vault_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.vaults_vault_id_seq OWNER TO postgres;

--
-- Name: vaults_vault_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.vaults_vault_id_seq OWNED BY public.vaults.vault_id;


--
-- Name: access_logs log_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.access_logs ALTER COLUMN log_id SET DEFAULT nextval('public.access_logs_log_id_seq'::regclass);


--
-- Name: auth_credentials auth_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_credentials ALTER COLUMN auth_id SET DEFAULT nextval('public.auth_credentials_auth_id_seq'::regclass);


--
-- Name: hardware_auth hardware_auth_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.hardware_auth ALTER COLUMN hardware_auth_id SET DEFAULT nextval('public.hardware_auth_hardware_auth_id_seq'::regclass);


--
-- Name: hardware_devices device_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.hardware_devices ALTER COLUMN device_id SET DEFAULT nextval('public.hardware_devices_device_id_seq'::regclass);


--
-- Name: users user_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users ALTER COLUMN user_id SET DEFAULT nextval('public.users_user_id_seq'::regclass);


--
-- Name: vault_data data_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vault_data ALTER COLUMN data_id SET DEFAULT nextval('public.vault_data_data_id_seq'::regclass);


--
-- Name: vault_policy policy_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vault_policy ALTER COLUMN policy_id SET DEFAULT nextval('public.vault_policy_policy_id_seq'::regclass);


--
-- Name: vaults vault_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vaults ALTER COLUMN vault_id SET DEFAULT nextval('public.vaults_vault_id_seq'::regclass);


--
-- Name: access_logs access_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.access_logs
    ADD CONSTRAINT access_logs_pkey PRIMARY KEY (log_id);


--
-- Name: auth_credentials auth_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_credentials
    ADD CONSTRAINT auth_credentials_pkey PRIMARY KEY (auth_id);


--
-- Name: auth_credentials auth_credentials_vault_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_credentials
    ADD CONSTRAINT auth_credentials_vault_id_key UNIQUE (vault_id);


--
-- Name: hardware_auth hardware_auth_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.hardware_auth
    ADD CONSTRAINT hardware_auth_pkey PRIMARY KEY (hardware_auth_id);


--
-- Name: hardware_auth hardware_auth_vault_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.hardware_auth
    ADD CONSTRAINT hardware_auth_vault_id_key UNIQUE (vault_id);


--
-- Name: hardware_devices hardware_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.hardware_devices
    ADD CONSTRAINT hardware_devices_pkey PRIMARY KEY (device_id);


--
-- Name: hardware_devices hardware_devices_vault_id_device_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.hardware_devices
    ADD CONSTRAINT hardware_devices_vault_id_device_name_key UNIQUE (vault_id, device_name);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: vault_data vault_data_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vault_data
    ADD CONSTRAINT vault_data_pkey PRIMARY KEY (data_id);


--
-- Name: vault_data vault_data_vault_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vault_data
    ADD CONSTRAINT vault_data_vault_id_key UNIQUE (vault_id);


--
-- Name: vault_policy vault_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vault_policy
    ADD CONSTRAINT vault_policy_pkey PRIMARY KEY (policy_id);


--
-- Name: vault_policy vault_policy_vault_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vault_policy
    ADD CONSTRAINT vault_policy_vault_id_key UNIQUE (vault_id);


--
-- Name: vaults vaults_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vaults
    ADD CONSTRAINT vaults_pkey PRIMARY KEY (vault_id);


--
-- Name: vaults vaults_user_id_vault_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vaults
    ADD CONSTRAINT vaults_user_id_vault_name_key UNIQUE (user_id, vault_name);


--
-- Name: access_logs access_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.access_logs
    ADD CONSTRAINT access_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: access_logs access_logs_vault_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.access_logs
    ADD CONSTRAINT access_logs_vault_id_fkey FOREIGN KEY (vault_id) REFERENCES public.vaults(vault_id);


--
-- Name: auth_credentials auth_credentials_vault_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_credentials
    ADD CONSTRAINT auth_credentials_vault_id_fkey FOREIGN KEY (vault_id) REFERENCES public.vaults(vault_id);


--
-- Name: hardware_auth hardware_auth_vault_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.hardware_auth
    ADD CONSTRAINT hardware_auth_vault_id_fkey FOREIGN KEY (vault_id) REFERENCES public.vaults(vault_id);


--
-- Name: hardware_devices hardware_devices_vault_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.hardware_devices
    ADD CONSTRAINT hardware_devices_vault_id_fkey FOREIGN KEY (vault_id) REFERENCES public.vaults(vault_id);


--
-- Name: vault_data vault_data_vault_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vault_data
    ADD CONSTRAINT vault_data_vault_id_fkey FOREIGN KEY (vault_id) REFERENCES public.vaults(vault_id);


--
-- Name: vault_policy vault_policy_vault_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vault_policy
    ADD CONSTRAINT vault_policy_vault_id_fkey FOREIGN KEY (vault_id) REFERENCES public.vaults(vault_id);


--
-- Name: vaults vaults_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vaults
    ADD CONSTRAINT vaults_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- PostgreSQL database dump complete
--

\unrestrict 7b6t4rtpFvpuD6Ak0qHl5aZIFd9ivLodQHrwYF53yQ8szuuTAAsFbTNDxzaGafu

