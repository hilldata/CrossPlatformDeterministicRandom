using System;

namespace XRD.Crypto {
  /// <summary>
  /// Class used to generate deterministic pseudo-random numbers for cryptographic operations.
  /// *NOT* suitable for "dice-rolling" apps.
  /// </summary>
	public sealed class XRanDom {
		private int m1, m2;

		public XRanDom(Guid seed) {
			if (seed.IsEmpty())
				throw new ArgumentNullException(nameof(seed));
			byte[] vs = seed.ToByteArray();
			for (int i = 0; i < 8; i++) {
				m1 ^= vs[i * 2];
				m2 &= vs[i * 2 + 1];
			}
			Next();
			vs.Wipe();
		}

		public XRanDom(long? seed = null) {
			byte[] x = new byte[4];
			byte[] y = new byte[4];
			byte[] t;
			if (seed.HasValue)
				t = BitConverter.GetBytes(seed.Value);
			else
				t = BitConverter.GetBytes(DateTime.UtcNow.Ticks);

			x[0] = t[4];
			x[1] = t[6];
			x[2] = t[0];
			x[3] = t[2];
			y[0] = t[7];
			y[1] = t[1];
			y[2] = t[4];
			y[3] = t[3];

			m1 = BitConverter.ToInt32(x, 0);
			m2 = BitConverter.ToInt32(y, 0);
			x.Wipe();
			y.Wipe();
			t.Wipe();
			Next();
		}

		internal XRanDom(int seed) {
			if (seed == 0) {
				byte[] x = new byte[4];
				byte[] y = new byte[4];
				byte[] t = BitConverter.GetBytes(DateTime.UtcNow.Ticks);

				x[0] = t[4];
				x[1] = t[6];
				x[2] = t[0];
				x[3] = t[2];
				y[0] = t[7];
				y[1] = t[1];
				y[2] = t[4];
				y[3] = t[3];
				m1 = BitConverter.ToInt32(x, 0);
				m2 = BitConverter.ToInt32(y, 0);
				x.Wipe();
				y.Wipe();
				t.Wipe();
				return;
			}

			byte[] a = BitConverter.GetBytes(seed);
			m1 = BitConverter.ToInt16(a, 0);
			m2 = BitConverter.ToInt16(a, 2);
			//Initial shuffle.
			Next();
		}

		public int Next(bool positiveOnly = false) {
			m1 = 10007 * (m1 & 65535) + (m1 >> 16);
			m2 = 44701 * (m2 & 65535) + (m2 << 16);
			if (positiveOnly)
				return Math.Abs(m1 ^ m2);
			else
				return m1 ^ m2;
		}

		internal void NextBytes(byte[] vs) {
			if (vs == null || vs.Length < 1)
				return;

			byte[] t = new byte[4];
			for (int i = 0; i < vs.Length; i++) {
				if (i % 4 == 0)
					t = BitConverter.GetBytes(Next());
				vs[i] = t[i % 4];
			}
		}

		internal byte[] NextBytes(int len) {
			if (len < 1 || len > short.MaxValue)
				throw new ArgumentOutOfRangeException(nameof(len));

			byte[] vs = new byte[len];
			byte[] t = new byte[4];
			for (int i = 0; i < len; i++) {
				if (i % 4 == 0)
					t = BitConverter.GetBytes(Next());
				vs[i] = t[i % 4];
			}
			t.Wipe();
			return vs;
		}
	}
}
