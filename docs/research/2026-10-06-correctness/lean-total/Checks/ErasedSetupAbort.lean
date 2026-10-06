import FooLiTotal.Controls
open MeasureTheory
-- FALSE: removing failed initialization attempts is not the raw experiment.
example : ((PMF.pure ()).bind (fun _ => PMF.pure true)).toMeasure.real {true} = 0 := by
  simp [Measure.real]
