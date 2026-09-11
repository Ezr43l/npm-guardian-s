"""Cerrojos compartidos por las operaciones locales que mutan NPM."""
import threading


# Renovar y crear un snapshot de réplica no pueden solaparse dentro del mismo
# Guardian. Los cambios iniciados por el propio NPM se detectan además mediante
# doble huella en replica.py.
# Reentrante porque la misma transacción de renovación debe crear y enviar el
# snapshot antes de liberar el cerrojo. Otros hilos siguen quedando excluidos.
escritura_npm = threading.RLock()
