#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Script desarrollado por Marcos Sebastián Cunioli – Especialista en Ciberseguridad
#
# Simulación didáctica de transacción con hashing y "firma" HMAC.
# ⚠️ No usar en producción. Es para visualización en clase.
#
# Ejecutar con:
#   streamlit run tx_demo_didactico_streamlit.py

import streamlit as st
import hashlib, hmac, json, secrets, time
from dataclasses import dataclass, asdict

st.set_page_config(page_title="Simulación de Transacción (Didáctica)", page_icon="🧪", layout="centered")

st.markdown("### **Marcos Cunioli** – *Especialista en Ciberseguridad*")
st.title("🧪 Simulación de Transacción")
st.caption("Hash (double-SHA256), 'firma' HMAC y verificación. *Propósito educativo.*")

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

@dataclass
class TxInput:
    prev_txid: str
    index: int

@dataclass
class TxOutput:
    address: str
    amount: int  # unidades enteras

@dataclass
class Transaction:
    version: int
    timestamp: int
    vin: list   # list[TxInput]
    vout: list  # list[TxOutput]
    memo: str = ""

    def serialize(self) -> bytes:
        obj = {
            "version": self.version,
            "timestamp": self.timestamp,
            "vin": [asdict(i) for i in self.vin],
            "vout": [asdict(o) for o in self.vout],
            "memo": self.memo
        }
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def txid(self) -> str:
        return sha256d(self.serialize()).hex()

# --- Estado ---
if "priv_key" not in st.session_state:
    st.session_state.priv_key = None
if "orig_signature" not in st.session_state:
    st.session_state.orig_signature = None
if "orig_serialization" not in st.session_state:
    st.session_state.orig_serialization = None

with st.sidebar:
    st.header("🎛️ Controles")
    if st.button("🔐 Generar clave privada didáctica", use_container_width=True):
        st.session_state.priv_key = secrets.token_bytes(32)
        st.session_state.orig_signature = None
        st.session_state.orig_serialization = None
    if st.session_state.priv_key:
        st.code(st.session_state.priv_key.hex(), language="text")
    else:
        st.info("Presioná **Generar clave privada** para comenzar.")

# Parámetros de transacción
st.subheader("🧩 Construcción de la Transacción")
col1, col2 = st.columns(2)
with col1:
    prev_txid = st.text_input("TX previa (prev_txid)", value=("a1"*32))
with col2:
    index = st.number_input("Índice del output previo (index)", min_value=0, value=0, step=1)

col3, col4 = st.columns(2)
with col3:
    addr_1 = st.text_input("Dirección destino #1", value="EDU1DESTINOAAAA1111")
    amt_1 = st.number_input("Monto #1 (unidades)", min_value=0, value=5000, step=100)
with col4:
    addr_2 = st.text_input("Dirección destino #2 (opcional)", value="EDU1DESTINOBBBB2222")
    amt_2 = st.number_input("Monto #2 (unidades)", min_value=0, value=1500, step=100)

memo = st.text_input("Memo (comentario)", value="Compra de materiales para el laboratorio")

if st.button("✍️ Construir & Firmar (HMAC)", use_container_width=True, disabled=(st.session_state.priv_key is None)):
    tx = Transaction(
        version=1,
        timestamp=int(time.time()),
        vin=[TxInput(prev_txid=prev_txid, index=int(index))],
        vout=[TxOutput(address=addr_1, amount=int(amt_1))] + ([TxOutput(address=addr_2, amount=int(amt_2))] if addr_2 and amt_2>0 else []),
        memo=memo
    )
    ser = tx.serialize()
    txid = tx.txid()
    signature = hmac_sha256(st.session_state.priv_key, ser).hex()

    st.session_state.orig_signature = signature
    st.session_state.orig_serialization = ser

    st.success("Transacción construida y firmada (didáctica).")
    st.json(json.loads(ser.decode("utf-8")))
    st.code(f"TXID (double-SHA256): {txid}", language="text")
    st.code(f"Firma HMAC-SHA256: {signature}", language="text")

st.divider()
st.subheader("🧪 Verificación y Alteración")

alter_memo = st.text_input("Alterar memo (prueba de integridad)", value=memo)
verify_click = st.button("🔍 Verificar con firma original", use_container_width=True, disabled=(st.session_state.orig_signature is None))

if verify_click and st.session_state.orig_serialization is not None:
    # Reemplazamos el memo en el JSON original de manera segura
    try:
        original = json.loads(st.session_state.orig_serialization)
        original["memo"] = alter_memo
        ser2 = json.dumps(original, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        txid2 = sha256d(ser2).hex()
        ok = (hmac_sha256(st.session_state.priv_key, ser2).hex() == st.session_state.orig_signature)
        st.json(original)
        st.code(f"Nuevo TXID: {txid2}", language="text")
        st.warning("Verificación con firma original: **OK** ✅" if ok else "Verificación con firma original: **FALLÓ** ❌")
        if not ok:
            st.caption("Cambiar cualquier campo altera el hash y la 'firma' ya no valida.")
    except Exception as e:
        st.error(f"Error al verificar: {e}")
elif st.session_state.orig_signature is None:
    st.info("Primero generá la transacción y la firma para poder verificar.")
