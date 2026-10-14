/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Matrice arithmetic             *
 * ****************************** */
 
#include <stdint.h>
#include "mat.h"
#include "param.h"
#include "poly.h"

/* Compute the Gram matrix a * (a*)^T */
void gram(MAT_FFT *out, const MAT_FFT *a, const uint64_t dim, const uint64_t n)
{
	uint64_t i, j, k, p;
	
	static MAT_FFT a_head;
	
	for (i = 0; i < dim; i++)
	{
		for (j = 0; j < dim; j++)
		{
			for (p = 0; p < N; p++)
			{
				a_head.mat[i][j].poly[p] = conjq(a->mat[i][j].poly[p]);
			}
		}
	}
	
	for (i = 0; i < dim; i++)
	{
		for (j = 0; j < dim; j++)
		{
			if (i == j)
			{
				for (p = 0; p < N; p++)
				{
					out->mat[i][j].poly[p] = crealq(a->mat[i][0].poly[p]) * crealq(a->mat[i][0].poly[p]) + cimagq(a->mat[i][0].poly[p]) * cimagq(a->mat[i][0].poly[p]);
					for (k = 1; k < dim; k++)
					{
						out->mat[i][j].poly[p] = out->mat[i][j].poly[p] + crealq(a->mat[i][k].poly[p]) * crealq(a->mat[i][k].poly[p]) + cimagq(a->mat[i][k].poly[p]) * cimagq(a->mat[i][k].poly[p]);
					}
				}
			}
			else
			{
				for (p = 0; p < N; p++)
				{
					out->mat[i][j].poly[p] = a->mat[i][0].poly[p] * a_head.mat[j][0].poly[p];
					for (k = 1; k < dim; k++)
					{
						out->mat[i][j].poly[p] = out->mat[i][j].poly[p] + a->mat[i][k].poly[p] * a_head.mat[j][k].poly[p];
					}
				}
			}
		}
	}
}
