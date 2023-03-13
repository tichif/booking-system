import { type FC, useState } from 'react';
import ReactCalendar from 'react-calendar';
import { add, format } from 'date-fns';

import {
  STORE_CLOSING_TIME,
  STORE_OPENING_TIME,
  INTERVAL,
} from '~/constants/config';

interface IProps {}

interface IDate {
  justDate: Date | null;
  dateTime: Date | null;
}

const Calendar: FC<IProps> = ({}) => {
  const [date, setDate] = useState<IDate>({
    justDate: null,
    dateTime: null,
  });

  const getTimes = () => {
    if (!date.justDate) {
      return;
    }

    const { justDate } = date;

    const beginning = add(justDate, { hours: STORE_OPENING_TIME });
    const end = add(justDate, { hours: STORE_CLOSING_TIME });
    const interval = INTERVAL;

    const times: Date[] = [];

    for (let i = beginning; i <= end; i = add(i, { minutes: interval })) {
      times.push(i);
    }

    return times;
  };

  const times = getTimes();

  return (
    <div className='flex h-screen flex-col items-center justify-center'>
      {date.justDate ? (
        <div className='flex gap-4'>
          {times?.map((time, i) => (
            <div key={`time-${i}`} className='rounded-sm bg-gray-100 p-2'>
              <button
                onClick={() => setDate((pre) => ({ ...pre, dateTime: time }))}
              >
                {format(time, 'kk:mm')}
              </button>
            </div>
          ))}
        </div>
      ) : (
        <ReactCalendar
          minDate={new Date()}
          className='REACT-CALENDAR p-2'
          view='month'
          onClickDay={(date) =>
            setDate((prev) => ({ ...prev, justDate: date }))
          }
        />
      )}
    </div>
  );
};

export default Calendar;