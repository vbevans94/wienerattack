package ua.org.cofriends.lab4;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class WienerAttack {

	// Four ArrayList for finding proper p/q which later on for guessing k/dg
	List<BigInteger> d = new ArrayList<BigInteger>();
	List<Fraction> a = new ArrayList<Fraction>();
	List<BigInteger> p = new ArrayList<BigInteger>();
	List<BigInteger> q = new ArrayList<BigInteger>();
	Fraction kDdg = new Fraction(BigInteger.ZERO, BigInteger.ONE); // k/dg, D
																	// means
																	// "divide"
	private BigInteger e;
	private BigInteger N;

	// get the root of BigInteger number
	public static BigInteger sqrt(BigInteger number) {
		BigInteger localBigInteger1 = BigInteger.valueOf(0L);
		BigInteger localBigInteger2 = localBigInteger1.setBit(2 * number.bitLength());
		do {
			BigInteger localBigInteger3 = localBigInteger1.add(localBigInteger2);
			if (localBigInteger3.compareTo(number) != 1) {
				number = number.subtract(localBigInteger3);
				localBigInteger1 = localBigInteger3.add(localBigInteger2);
			}
			localBigInteger1 = localBigInteger1.shiftRight(1);
			localBigInteger2 = localBigInteger2.shiftRight(2);
		} while (localBigInteger2.bitCount() != 0);
		return localBigInteger1;
	}

	/**
	 * Attacks given public key and modulos.
	 * 
	 * @param e
	 *            public key
	 * @param N
	 *            modulos which needs to be factorized
	 * @return
	 */
	public BigInteger attack(BigInteger e, BigInteger N) {
		this.e = e;
		this.N = N;
		int i = 0;
		BigInteger temp1;

		// This loop keeps going unless the privateKey is calculated or no
		// privateKey is generated
		// When no privateKey is generated, temp1 == -1
		while ((temp1 = step(i)) == null) {
			i++;
		}

		return temp1;
	}

	public BigInteger step(int iteration) {
		if (iteration == 0) {
			// initialization for iteration 0
			Fraction ini = new Fraction(e, N);
			d.add(ini.floor());
			a.add(ini.remainder());
			p.add(d.get(0));
			q.add(BigInteger.ONE);
		} else if (iteration == 1) {
			// iteration 1
			Fraction temp2 = new Fraction(a.get(0).denominator, a.get(0).numerator);
			d.add(temp2.floor());
			a.add(temp2.remainder());
			p.add((d.get(0).multiply(d.get(1))).add(BigInteger.ONE));
			q.add(d.get(1));
		} else {
			if (a.get(iteration - 1).numerator.equals(BigInteger.ZERO)) {
				return BigInteger.ONE.negate(); // Finite continued fraction.
												// and no proper privateKey
												// could be generated. Return -1
			}

			// go on calculating p and q for iteration i by using formulas
			// stating on the paper
			Fraction temp3 = new Fraction(a.get(iteration - 1).denominator, a.get(iteration - 1).numerator);
			d.add(temp3.floor());
			a.add(temp3.remainder());
			p.add((d.get(iteration).multiply(p.get(iteration - 1)).add(p.get(iteration - 2))));
			q.add((d.get(iteration).multiply(q.get(iteration - 1)).add(q.get(iteration - 2))));
		}

		// if iteration is even, assign <q0, q1, q2,...,qi+1> to kDdg
		if (iteration % 2 == 0) {
			if (iteration == 0) {
				kDdg = new Fraction(d.get(0).add(BigInteger.ONE), BigInteger.ONE);
			} else {
				kDdg = new Fraction((d.get(iteration).add(BigInteger.ONE)).multiply(p.get(iteration - 1)).add(
						p.get(iteration - 2)), (d.get(iteration).add(BigInteger.ONE)).multiply(q.get(iteration - 1))
						.add(q.get(iteration - 2)));
			}
		}

		// if iteration is odd, assign <q0, q1, q2,...,qi> to kDdg
		else {
			kDdg = new Fraction(p.get(iteration), q.get(iteration));
		}
		
		System.out.println(kDdg);
		
		
		BigInteger 	phi = e.multiply(kDdg.denominator).subtract(BigInteger.ONE).divide(kDdg.numerator);
		BigInteger b = N.subtract(phi).add(BigInteger.ONE);
		BigInteger c = N;
		BigInteger descriminant = b.multiply(b).subtract(new BigInteger("4").multiply(c));
		BigInteger x1 = b.negate().add(sqrt(descriminant)).divide(new BigInteger("2")).abs();
		BigInteger x2 = b.negate().subtract(sqrt(descriminant)).divide(new BigInteger("2")).abs();

		if (x1.multiply(x2).equals(N)) {
			return e.modInverse(phi);
		}
		
		BigInteger edg = this.e.multiply(kDdg.denominator); // get edg from e *
															// dg
		

		// dividing edg by k yields a quotient of (p-1)(d-1) and a remainder of
		// g
		BigInteger fy = (new Fraction(this.e, kDdg)).floor();
		BigInteger g = edg.mod(kDdg.numerator);

		// get (p+d)/2 and check whether (p+d)/2 is integer or not
		BigDecimal pAqD2 = (new BigDecimal(this.N.subtract(fy))).add(BigDecimal.ONE).divide(new BigDecimal("2"));
		if (!pAqD2.remainder(BigDecimal.ONE).equals(BigDecimal.ZERO))
			return null;

		// get [(p-d)/2]^2 and check [(p-d)/2]^2 is a perfect square or not
		BigInteger pMqD2s = pAqD2.toBigInteger().pow(2).subtract(N);
		BigInteger pMqD2 = sqrt(pMqD2s);
		if (!pMqD2.pow(2).equals(pMqD2s))
			return null;

		// get private key q from edg/eg
		BigInteger privateKey = edg.divide(e.multiply(g));
		return privateKey;

	}
}
