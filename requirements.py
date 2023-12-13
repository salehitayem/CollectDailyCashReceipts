import os

import datetime
from decimal import Decimal, ROUND_HALF_EVEN
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import pytz
from helpers import login_required, apology
from flask import jsonify
from datetime import datetime, timezone, timedelta
import json
from database import app, db